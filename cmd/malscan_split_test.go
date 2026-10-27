package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulnetix/cli/v3/internal/ecosystems"
	"github.com/vulnetix/malscan-engine/iocscan"
)

// The split walk must give exactly the report of one walk of the whole target:
// the same evidence, in the same order, with the same paths, classes and
// lines, and the same file count. The tree exercises every way the engine
// reads a path: files at the root, test/dist/example directories below an
// entry, minified bundles and lines, Markdown, a binary, a scoped package and
// a skipped directory.
func TestIOCScanSplitMatchesWholeWalk(t *testing.T) {
	root := t.TempDir()
	ioc := "fetch('http://c2-badhost.xyz/beacon'); connect('45.137.21.9:443')\n"
	minified := "var a=1;" + strings.Repeat("x=c2-badhost.xyz;", 200) + "\n"
	files := map[string]string{
		"a-root.js":                       ioc,
		"zz-root.txt":                     "nothing here\n" + ioc,
		"README.md":                       ioc,
		"alpha/index.js":                  "ok\n" + ioc + "ok\n" + ioc,
		"alpha/test/fixture.js":           ioc,
		"alpha/dist/bundle.js":            ioc,
		"alpha/lib/app.min.js":            ioc,
		"alpha/lib/long.js":               minified,
		"alpha/examples/demo.js":          ioc,
		"alpha/docs/guide.md":             ioc,
		"beta/src/x.spec.js":              ioc,
		"beta/src/y.js":                   ioc,
		"beta/map/z.js.map":               ioc,
		"@scope/pkg/index.js":             ioc,
		"@scope/pkg/node_modules/n/i.js":  ioc,
		"gamma/bin/tool":                  "\x7fELF\x00\x00" + strings.Repeat("A", 8) + "http://c2-badhost.xyz/bin\x00more",
		"gamma/deep/er/still/deeper/q.js": ioc,
		"node_modules/nested/index.js":    ioc,
		".git/config":                     ioc,
		"delta.js":                        ioc,
	}
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
	}

	set := iocscan.NewIndicatorSet()
	set.Add(&iocscan.Indicator{Type: iocscan.TypeDomain, Value: "c2-badhost.xyz", Name: "test-c2", Severity: "high"})
	set.Add(&iocscan.Indicator{Type: iocscan.TypeIPv4, Value: "45.137.21.9", Name: "test-ip"})
	set.Add(&iocscan.Indicator{Type: iocscan.TypeURL, Value: "http://c2-badhost.xyz/beacon", Name: "test-url"})

	opts := malscanOptions{BinaryAnalysis: true}
	whole, err := iocscan.Scan(iocscan.Options{
		Root:           root,
		Set:            set,
		BinaryAnalysis: true,
		ContextLines:   iocscan.DefaultContextLines,
		SkipDirs:       ecosystems.ScanSkipDirs(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, whole.Evidence, "the tree must produce evidence for this test to mean anything")

	entries, ok := splittableEntries(root, opts)
	require.True(t, ok)
	split := scanEntries(root, entries, opts, set)
	require.Equal(t, whole.FilesScanned, split.FilesScanned)
	require.Equal(t, whole.IndicatorCount, split.IndicatorCount)
	require.Equal(t, whole.Evidence, split.Evidence)
}

func TestIOCScanSplitDeclinesWhatItCannotReproduce(t *testing.T) {
	mk := func(dirs ...string) string {
		root := t.TempDir()
		for _, d := range dirs {
			require.NoError(t, os.MkdirAll(filepath.Join(root, d), 0o755))
		}
		return root
	}
	_, ok := splittableEntries(mk("a", "b"), malscanOptions{})
	require.True(t, ok)
	_, ok = splittableEntries(mk("a", "Dist"), malscanOptions{})
	require.False(t, ok, "an entry the engine classifies by name is walked whole")
	_, ok = splittableEntries(mk("a", "test"), malscanOptions{})
	require.False(t, ok)
	_, ok = splittableEntries(mk("a", "b"), malscanOptions{Depth: 3})
	require.False(t, ok, "a depth limit counts from the walk's root")
	_, ok = splittableEntries(mk("a"), malscanOptions{})
	require.False(t, ok, "one directory is one walk either way")
}

// malscanTierSegments copies the directory names malscan-engine v0.6.1
// classifies paths by. A different engine may classify by others, which would
// make a split walk classify a file differently from the whole walk.
func TestMalscanEnginePinnedForSplit(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join("..", "go.mod"))
	require.NoError(t, err)
	require.Contains(t, string(mod), "github.com/vulnetix/malscan-engine v0.6.1",
		"malscan-engine changed: check malscanTierSegments (cmd/malscan_split.go) against its iocFileTier, then update this pin")
}
