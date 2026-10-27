package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulnetix/cli/v3/internal/reachability"
)

func newTestEngine() *reachability.Engine { return reachability.NewEngine() }

// writeGraphFixture is a small tree that exercises everything order-sensitive in the graph
// merge: paths that sanitise to the same record id, a symbol name repeated in one file, local
// imports and calls, and one egress host named from several files with different evidence.
func writeGraphFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.22\n",
		"main.go": `package main

import "example.com/app/lib"

func init() {}
func init() {}

func main() {
	lib.Fetch()
	helper()
}

func helper() { if true { for {} } }
`,
		"lib/fetch.go": `package lib

import "net/http"

func Fetch() { http.Get("https://api.acme-cdn.io/v1") }
`,
		"a-b.go":               "package main\n\nfunc dash() {}\n",
		"a_b.go":               "package main\n\nfunc under() {}\n",
		"web/app.js":           "import { x } from './util.js'\nfunction run() { fetch('https://api.acme-cdn.io/x'); x() }\n",
		"web/util.js":          "export function x() { return 1 }\n",
		"deploy/ci.yaml":       "steps:\n  - run: curl https://api.acme-cdn.io/health\n  - url: https://downloads.example-mirror.net/tool\n",
		"README.md":            "See https://docs.acme-cdn.io for the API.\n",
		".vulnetix/sast.sarif": `{"runs":[{"tool":{"driver":{"informationUri":"https://scanner-output.example.org"}}}]}`,
	}
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
	}
	return root
}

func graphReport(t *testing.T, root string, opts Options) []byte {
	t.Helper()
	opts.Path, opts.NoGit, opts.NoTrust, opts.NoForge, opts.Silent = root, true, true, true, true
	opts.ComplexityThreshold = 15
	_, body, err := RunGraphOnly(Tool{Name: "vulnetix-static-graph", Version: "test"}, opts, nil)
	require.NoError(t, err)
	norm, err := normalisedReport(body)
	require.NoError(t, err)
	return norm
}

func graphParityRoots(t *testing.T) []string {
	roots := []string{writeGraphFixture(t)}
	if _, err := os.Stat(filepath.Join("..", "..", "testdata", "vulnetix-fixture-app", "src")); err == nil {
		roots = append(roots, filepath.Join("..", "..", "testdata", "vulnetix-fixture-app"))
	}
	return roots
}

// The files are read in parallel and merged in walk order, so the report must not depend on
// how many workers read them.
func TestGraphOnlyConcurrencyParity(t *testing.T) {
	for _, root := range graphParityRoots(t) {
		serial := graphReport(t, root, Options{Workers: 1})
		require.Equal(t, string(serial), string(graphReport(t, root, Options{Workers: 8})), root)
	}
}

// A cache hit is exactly what parsing produces: cold, warm and uncached runs agree, an edited
// file is read again, and a deleted file drops out.
func TestGraphOnlyCacheParity(t *testing.T) {
	root := writeGraphFixture(t)
	cached := Options{CacheDir: t.TempDir(), CacheSalt: "test-build"}

	base := graphReport(t, root, Options{})
	require.Equal(t, string(base), string(graphReport(t, root, cached)), "cold")
	require.Equal(t, string(base), string(graphReport(t, root, cached)), "warm")

	require.NoError(t, os.WriteFile(filepath.Join(root, "lib", "fetch.go"),
		[]byte("package lib\n\nimport \"net/http\"\n\nfunc Fetch() { http.Get(\"https://other-host.example.io/v1\") }\nfunc Extra() {}\n"), 0o644))
	require.NoError(t, os.Remove(filepath.Join(root, "a_b.go")))
	edited := graphReport(t, root, Options{})
	require.NotEqual(t, string(base), string(edited))
	require.Equal(t, string(edited), string(graphReport(t, root, cached)), "after an edit and a delete")
}

// The scanner's own output is not the repository's: a host named only in .vulnetix/ is not
// egress.
func TestGraphOnlySkipsScannerOutput(t *testing.T) {
	report := string(graphReport(t, writeGraphFixture(t), Options{}))
	require.Contains(t, report, "api.acme-cdn.io")
	require.NotContains(t, report, "scanner-output.example.org")
}

// One parse running every query gives what one parse per query gave.
func TestComputeFileFactsMatchesSeparateQueries(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(writeGraphFixture(t), "main.go"))
	require.NoError(t, err)
	engine := newTestEngine()
	ff := computeFileFacts(t.Context(), engine, "go", src)
	require.Equal(t, queryRan, ff.Decision)
	require.Equal(t, queryRan, ff.Symbol)
	require.Equal(t, queryRan, ff.Call)

	dm, err := engine.Run(t.Context(), "go", src, decisionQueries["go"])
	require.NoError(t, err)
	require.Equal(t, len(dm)+1, *ff.Complexity)
	sm, err := engine.Run(t.Context(), "go", src, symbolQueries["go"])
	require.NoError(t, err)
	require.Len(t, ff.Symbols, len(sm))
	cm, err := engine.Run(t.Context(), "go", src, callQueries["go"])
	require.NoError(t, err)
	require.Len(t, ff.Calls, len(cm))
}
