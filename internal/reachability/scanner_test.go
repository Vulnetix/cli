package reachability

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// writeTempProject creates a temp dir populated with the given relative-path →
// content files and returns the dir.
func writeTempProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// A JS query that matches member-call expressions like `_.template(x)`.
const jsMemberCallQuery = `(call_expression function: (member_expression) @callee)`

func TestScanExecuted_NoMatchingFiles(t *testing.T) {
	// Project contains only a .py file; the query is for JavaScript. The query
	// never runs against any file, so its key must be absent from Executed.
	root := writeTempProject(t, map[string]string{
		"main.py": "x = 1\n",
	})
	q := vdb.TreeSitterQuery{
		VulnID:    "CVE-NOFILE",
		Language:  "javascript",
		Name:      "js-member-call",
		QueryText: jsMemberCallQuery,
		QueryHash: "hash-nofile",
	}
	res, err := Scan(context.Background(), NewEngine(), ScanRequest{
		ProjectRoot: root,
		Queries:     []vdb.TreeSitterQuery{q},
		Mode:        ModeTransitive,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Executed[QueryKey(q)] {
		t.Errorf("query with no matching-language files should not be Executed; Executed=%v", res.Executed)
	}
	if len(res.Transitive) != 0 {
		t.Errorf("expected no matches, got %d", len(res.Transitive))
	}
}

func TestScanExecuted_RanButNoMatch(t *testing.T) {
	// Project has a .js file but the code doesn't contain a member-call, so the
	// query runs (compiles + executes) but matches nothing. Its key MUST be in
	// Executed — this is genuine evidence of non-reachability.
	root := writeTempProject(t, map[string]string{
		"app.js": "const a = 1;\nconst b = a + 2;\n",
	})
	q := vdb.TreeSitterQuery{
		VulnID:    "CVE-NOMATCH",
		Language:  "javascript",
		Name:      "js-member-call",
		QueryText: jsMemberCallQuery,
		QueryHash: "hash-nomatch",
	}
	res, err := Scan(context.Background(), NewEngine(), ScanRequest{
		ProjectRoot: root,
		Queries:     []vdb.TreeSitterQuery{q},
		Mode:        ModeTransitive,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.Executed[QueryKey(q)] {
		t.Errorf("query that ran against a matching file should be Executed; Executed=%v", res.Executed)
	}
	if len(res.Transitive) != 0 {
		t.Errorf("expected no matches, got %d", len(res.Transitive))
	}
}

func TestScanExecuted_Matched(t *testing.T) {
	root := writeTempProject(t, map[string]string{
		"render.js": "const _ = require('lodash');\nfunction r(i){ return _.template(i); }\n",
	})
	q := vdb.TreeSitterQuery{
		VulnID:    "CVE-MATCH",
		Language:  "javascript",
		Name:      "js-member-call",
		QueryText: jsMemberCallQuery,
		QueryHash: "hash-match",
	}
	res, err := Scan(context.Background(), NewEngine(), ScanRequest{
		ProjectRoot: root,
		Queries:     []vdb.TreeSitterQuery{q},
		Mode:        ModeTransitive,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.Executed[QueryKey(q)] {
		t.Errorf("matched query should be Executed; Executed=%v", res.Executed)
	}
	if len(res.Transitive) == 0 {
		t.Errorf("expected at least one match")
	}
}

func TestScanExecuted_UnsupportedLanguageDropped(t *testing.T) {
	// An unsupported-language query is dropped before scanning; even with files
	// present it must never appear in Executed.
	root := writeTempProject(t, map[string]string{
		"app.js": "const _ = require('lodash'); _.template('x');\n",
	})
	q := vdb.TreeSitterQuery{
		VulnID:    "CVE-UNSUPPORTED",
		Language:  "klingon",
		Name:      "unsupported",
		QueryText: jsMemberCallQuery,
		QueryHash: "hash-unsupported",
	}
	res, err := Scan(context.Background(), NewEngine(), ScanRequest{
		ProjectRoot: root,
		Queries:     []vdb.TreeSitterQuery{q},
		Mode:        ModeTransitive,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Executed[QueryKey(q)] {
		t.Errorf("unsupported-language query should never be Executed; Executed=%v", res.Executed)
	}
}

func TestQueryKey(t *testing.T) {
	withHash := vdb.TreeSitterQuery{Name: "n", Language: "javascript", QueryHash: "abc"}
	if got := QueryKey(withHash); got != "abc" {
		t.Errorf("QueryKey with hash = %q, want %q", got, "abc")
	}
	noHash := vdb.TreeSitterQuery{Name: "n", Language: "js"}
	if got := QueryKey(noHash); got != "n:javascript" {
		t.Errorf("QueryKey without hash = %q, want %q (language must be normalised)", got, "n:javascript")
	}
}
