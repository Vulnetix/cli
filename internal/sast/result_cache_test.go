package sast

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResultCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := resultCacheKey("build-1", map[string]string{"r.rego": "package vulnetix.rules.r"})

	c := openResultCache(dir, "/repo", key)
	_, ok := c.lookup("a.py", contentSHA("x"))
	require.False(t, ok, "a new cache is empty")

	f := Finding{RuleID: "VNX-1", ArtifactURI: "a.py", StartLine: 3, Message: "m", Snippet: "eval(x)", Severity: "high", Level: "error"}
	c.save(map[string]cachedFile{
		"a.py": {SHA: contentSHA("x"), Findings: []Finding{f}},
		"b.py": {SHA: contentSHA("clean")},
	})

	c = openResultCache(dir, "/repo", key)
	got, ok := c.lookup("a.py", contentSHA("x"))
	require.True(t, ok)
	require.Equal(t, []Finding{f}, got)
	got, ok = c.lookup("b.py", contentSHA("clean"))
	require.True(t, ok, "a clean file is a hit too")
	require.Empty(t, got)

	_, ok = c.lookup("a.py", contentSHA("x changed"))
	require.False(t, ok, "edited text is a miss")
	_, ok = openResultCache(dir, "/other", key).lookup("a.py", contentSHA("x"))
	require.False(t, ok, "another scan root has its own cache")
	_, ok = openResultCache(dir, "/repo", resultCacheKey("build-2", nil)).lookup("a.py", contentSHA("x"))
	require.False(t, ok, "another build or rule set has its own cache")
}

func TestResultCacheKeyCoversModulesAndBuild(t *testing.T) {
	mods := map[string]string{"r.rego": "package vulnetix.rules.r\nx := 1"}
	edited := map[string]string{"r.rego": "package vulnetix.rules.r\nx := 2"}
	require.Equal(t, resultCacheKey("b", mods), resultCacheKey("b", mods))
	require.NotEqual(t, resultCacheKey("b", mods), resultCacheKey("b", edited))
	require.NotEqual(t, resultCacheKey("b", mods), resultCacheKey("c", mods))
}

func TestResultCacheUnreadableIsEmpty(t *testing.T) {
	dir := t.TempDir()
	c := openResultCache(dir, "/repo", "k")
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path), 0o700))
	require.NoError(t, os.WriteFile(c.path, []byte("{not json"), 0o600))
	_, ok := openResultCache(dir, "/repo", "k").lookup("a", contentSHA(""))
	require.False(t, ok)
}

func TestPruneResultCaches(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i, name := range []string{"a.json", "b.json", "c.json", "d.json", "e.json"} {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("{}"), 0o600))
		require.NoError(t, os.Chtimes(p, now, now.Add(-time.Duration(i)*time.Hour)))
	}
	pruneResultCaches(dir, 3)
	left, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range left {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, []string{"a.json", "b.json", "c.json"}, names, "the newest three are kept")
}

// A warm cache is a performance change only: the same findings, with
// fingerprints and metadata, and an edited file is evaluated again.
func TestCachedEvaluationParity(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates every embedded rule several times")
	}
	fixture := filepath.Join("..", "..", "testdata", "vulnetix-fixture-app")
	if _, err := os.Stat(filepath.Join(fixture, "src", "vuln.go")); err != nil {
		t.Skip("fixture app submodule not checked out")
	}
	root := t.TempDir()
	require.NoError(t, os.CopyFS(root, os.DirFS(fixture)))
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)
	cacheDir := t.TempDir()

	run := func(cached bool) *SASTReport {
		t.Helper()
		opts := EvalOptions{MaxDepth: 8}
		if cached {
			opts.CacheDir, opts.CacheSalt = cacheDir, "test-build"
		}
		rep, err := NewEngine(modules, root).Evaluate(opts)
		require.NoError(t, err)
		return rep
	}
	same := func(want, got *SASTReport) {
		t.Helper()
		require.Equal(t, findingKeys(want.Findings), findingKeys(got.Findings))
		for _, f := range got.Findings {
			require.Equal(t, Fingerprint(f.RuleID, f.ArtifactURI, f.StartLine), f.Fingerprint)
			require.NotNil(t, f.Metadata, "%s on %s has no metadata", f.RuleID, f.ArtifactURI)
		}
	}

	base := run(false)
	require.NotEmpty(t, base.Findings)
	cold := run(true)
	same(base, cold)
	require.Zero(t, cold.CachedFiles)
	require.Positive(t, cold.EvaluatedFiles)

	warm := run(true)
	same(base, warm)
	require.Zero(t, warm.EvaluatedFiles, "nothing changed, so nothing is evaluated again")
	require.Equal(t, cold.EvaluatedFiles, warm.CachedFiles)

	vuln := filepath.Join(root, "src", "vuln.go")
	src, err := os.ReadFile(vuln)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(vuln, append([]byte("// edited\n"), src...), 0o644))
	edited := run(true)
	same(run(false), edited)
	require.Equal(t, 1, edited.EvaluatedFiles, "only the edited file is evaluated again")
}
