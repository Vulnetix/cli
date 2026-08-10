package sast

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func baseInput() *ScanInput {
	return &ScanInput{
		FileSet:        map[string]bool{"a.go": true, "b.go": true, "go.mod": true},
		DirsByLanguage: map[string][]string{"go": {"."}},
		FileContents: map[string]string{
			"a.go":   "package a\n",
			"b.go":   "package b\n",
			"go.mod": "module x\n",
		},
		ScanRoot: "/repo",
	}
}

func TestOverlayReplacesContentsButKeepsTheFileSet(t *testing.T) {
	base := baseInput()
	got := Overlay(base, map[string]string{"a.go": "package a // edited\n"})

	require.Equal(t, map[string]string{"a.go": "package a // edited\n"}, got.FileContents,
		"the keystroke path evaluates only the dirty document")

	// Path-existence rules must still see the whole repository, or a rule
	// keyed on "there is a go.mod here" would stop firing while you type.
	require.True(t, got.FileSet["b.go"])
	require.True(t, got.FileSet["go.mod"])
	require.Equal(t, base.DirsByLanguage, got.DirsByLanguage)
	require.Equal(t, base.ScanRoot, got.ScanRoot)
}

func TestOverlayDoesNotMutateTheBase(t *testing.T) {
	// The base is shared across concurrent evaluations, so mutating it would
	// be a data race with whatever else is mid-scan.
	base := baseInput()
	Overlay(base, map[string]string{"a.go": "edited\n", "brand-new.go": "package new\n"})

	require.Equal(t, "package a\n", base.FileContents["a.go"], "base contents unchanged")
	require.False(t, base.FileSet["brand-new.go"], "base file set unchanged")
	require.Len(t, base.FileSet, 3)
}

func TestOverlaySharesTheFileSetWhenNothingIsNew(t *testing.T) {
	// Copying a 50k-entry map on every keystroke would be the single largest
	// allocation on the hot path, so it is shared when it can be.
	base := baseInput()
	got := Overlay(base, map[string]string{"a.go": "edited\n"})

	require.Len(t, got.FileSet, len(base.FileSet))
	// Same underlying map: mutating one would be visible in the other, which
	// is exactly why evaluation treats it as read-only.
	base.FileSet["probe"] = true
	require.True(t, got.FileSet["probe"], "the file set should be shared, not copied, when nothing is new")
}

func TestOverlayAddsUnknownDocumentsToTheFileSet(t *testing.T) {
	// A file created in the editor and not yet on disk is absent from the last
	// index. Without this, rules keyed on its existence never fire until a
	// rescan.
	base := baseInput()
	got := Overlay(base, map[string]string{"brand-new.go": "package new\n"})

	require.True(t, got.FileSet["brand-new.go"])
	require.True(t, got.FileSet["a.go"], "existing entries survive")
	require.False(t, base.FileSet["brand-new.go"], "and the base is left alone")
}

func TestOverlayWithNilBase(t *testing.T) {
	got := Overlay(nil, map[string]string{"a.go": "x"})
	require.Equal(t, map[string]string{"a.go": "x"}, got.FileContents)
	require.NotNil(t, got.FileSet)
	require.NotNil(t, got.DirsByLanguage)
}

func TestOverlayOntoMergesRatherThanReplaces(t *testing.T) {
	// The save path evaluates the whole repository with the editor's version of
	// the dirty buffers in place of what is on disk.
	base := baseInput()
	got := OverlayOnto(base, map[string]string{"a.go": "package a // unsaved\n"})

	require.Equal(t, "package a // unsaved\n", got.FileContents["a.go"], "the buffer wins over disk")
	require.Equal(t, "package b\n", got.FileContents["b.go"], "untouched files are still present")
	require.Len(t, got.FileContents, 3)
	require.Equal(t, "package a\n", base.FileContents["a.go"], "the base is unchanged")
}

// ── BuildScanInputContext ────────────────────────────────────────────────────

func TestBuildScanInputContextReturnsAWalk(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644))

	in, err := BuildScanInputContext(context.Background(), root, BuildOptions{MaxDepth: 5})
	require.NoError(t, err)
	require.True(t, in.FileSet["main.go"])
	require.True(t, in.FileSet["go.mod"])
}

func TestBuildScanInputContextHonoursAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := BuildScanInputContext(ctx, t.TempDir(), BuildOptions{})
	require.ErrorIs(t, err, context.Canceled,
		"a cancelled scan must be distinguishable from a failed one")
}

func TestBuildScanInputContextMatchesTheUncancellableVariant(t *testing.T) {
	// The two entry points must not drift in what they include, or a workspace
	// scan and a cancellable one would disagree about the repository.
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pkg"), 0o755))
	for _, f := range []string{"main.go", "go.mod", "pkg/a.go", "README.md"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, f), []byte("x\n"), 0o644))
	}

	want, err := BuildScanInputWithOptions(root, BuildOptions{MaxDepth: 5})
	require.NoError(t, err)
	got, err := BuildScanInputContext(context.Background(), root, BuildOptions{MaxDepth: 5})
	require.NoError(t, err)

	require.Equal(t, want.FileSet, got.FileSet)
	require.Equal(t, want.DirsByLanguage, got.DirsByLanguage)
}

// ── Budgeted content loading ─────────────────────────────────────────────────

// repoWithFiles writes n files of the given size and returns a ScanInput whose
// FileSet names them.
func repoWithFiles(t *testing.T, n int, size int) (*ScanInput, string) {
	t.Helper()
	root := t.TempDir()
	body := strings.Repeat("x", size)
	fileSet := make(map[string]bool, n)
	for i := range n {
		name := fmt.Sprintf("f%03d.txt", i)
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(body), 0o644))
		fileSet[name] = true
	}
	return &ScanInput{
		FileSet:        fileSet,
		DirsByLanguage: map[string][]string{},
		ScanRoot:       root,
	}, root
}

func TestLoadFileContentsBudgetedLoadsEverythingUnderBudget(t *testing.T) {
	in, _ := repoWithFiles(t, 10, 100)

	res, err := LoadFileContentsBudgeted(context.Background(), in, LoadOptions{MaxFileSize: 1 << 20}, 1<<20)
	require.NoError(t, err)
	require.Equal(t, 10, res.Loaded)
	require.False(t, res.TruncatedAtBudget)
	require.Empty(t, res.Degradations())
	require.Len(t, in.FileContents, 10)
}

func TestLoadFileContentsBudgetedStopsAtTheAggregateCeiling(t *testing.T) {
	// The gap this closes: LoadFileContentsWithOptions caps each file but
	// nothing caps the total, so enough small files still exhaust memory.
	in, _ := repoWithFiles(t, 100, 1000)

	res, err := LoadFileContentsBudgeted(context.Background(), in, LoadOptions{MaxFileSize: 1 << 20}, 10_000)
	require.NoError(t, err)
	require.True(t, res.TruncatedAtBudget)
	require.LessOrEqual(t, res.TotalBytes, int64(10_000))
	require.Less(t, res.Loaded, 100)
	require.Contains(t, strings.Join(res.Degradations(), " "), "memory budget",
		"a truncated scan must say so rather than reading as clean")
}

func TestLoadFileContentsBudgetedTruncatesDeterministically(t *testing.T) {
	// Map iteration order is random, so without sorting the same repository
	// would truncate at a different point each run and a partial scan would be
	// irreproducible.
	in1, root := repoWithFiles(t, 60, 1000)
	res1, err := LoadFileContentsBudgeted(context.Background(), in1, LoadOptions{MaxFileSize: 1 << 20}, 10_000)
	require.NoError(t, err)
	require.True(t, res1.TruncatedAtBudget)

	for range 5 {
		in2 := &ScanInput{FileSet: in1.FileSet, DirsByLanguage: map[string][]string{}, ScanRoot: root}
		res2, err := LoadFileContentsBudgeted(context.Background(), in2, LoadOptions{MaxFileSize: 1 << 20}, 10_000)
		require.NoError(t, err)
		require.Equal(t, res1.Loaded, res2.Loaded)
		require.Equal(t, keysOf(in1.FileContents), keysOf(in2.FileContents))
	}
}

func TestLoadFileContentsBudgetedReportsOversizedFiles(t *testing.T) {
	in, root := repoWithFiles(t, 2, 100)
	require.NoError(t, os.WriteFile(filepath.Join(root, "big.txt"), []byte(strings.Repeat("x", 5000)), 0o644))
	in.FileSet["big.txt"] = true

	res, err := LoadFileContentsBudgeted(context.Background(), in, LoadOptions{MaxFileSize: 1000}, 1<<20)
	require.NoError(t, err)
	require.Equal(t, 1, res.SkippedTooLarge)
	require.NotContains(t, in.FileContents, "big.txt")
	require.Contains(t, strings.Join(res.Degradations(), " "), "not content-scanned")
}

func TestLoadFileContentsBudgetedReportsUnreadableFiles(t *testing.T) {
	in, _ := repoWithFiles(t, 1, 10)
	in.FileSet["does-not-exist.txt"] = true

	res, err := LoadFileContentsBudgeted(context.Background(), in, LoadOptions{MaxFileSize: 1 << 20}, 1<<20)
	require.NoError(t, err)
	require.Equal(t, 1, res.SkippedUnreadable)
	require.Contains(t, strings.Join(res.Degradations(), " "), "unreadable")
}

func TestLoadFileContentsBudgetedIsCancellable(t *testing.T) {
	in, _ := repoWithFiles(t, 2000, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := LoadFileContentsBudgeted(ctx, in, LoadOptions{MaxFileSize: 1 << 20}, 1<<30)
	require.ErrorIs(t, err, context.Canceled)
}

func TestLoadFileContentsBudgetedZeroBudgetMeansUnlimited(t *testing.T) {
	// Zero is the CLI's setting: a one-shot process does not need a ceiling.
	in, _ := repoWithFiles(t, 50, 1000)

	res, err := LoadFileContentsBudgeted(context.Background(), in, LoadOptions{MaxFileSize: 1 << 20}, 0)
	require.NoError(t, err)
	require.Equal(t, 50, res.Loaded)
	require.False(t, res.TruncatedAtBudget)
}

func TestLoadContentsResultDegradationsGrammar(t *testing.T) {
	require.Equal(t,
		[]string{"1 file was not content-scanned (over the per-file size cap)"},
		LoadContentsResult{SkippedTooLarge: 1}.Degradations())
	require.Equal(t,
		[]string{"3 files were not content-scanned (over the per-file size cap)"},
		LoadContentsResult{SkippedTooLarge: 3}.Degradations())
	require.Empty(t, LoadContentsResult{Loaded: 5}.Degradations())
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
