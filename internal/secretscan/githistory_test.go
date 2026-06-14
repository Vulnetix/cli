package secretscan

import (
	"os/exec"
	"strings"
	"testing"
)

// TestScanGitHistory_OnCLIRepo exercises the git-history scanner against the
// current vulnetix/cli repository. The CLI repo has thousands of commits, so
// we cap the walk to keep the test fast.
func TestScanGitHistory_OnCLIRepo(t *testing.T) {
	// Find the git root for this test by shelling out.
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not running inside a git checkout: %v", err)
	}
	root := strings.TrimSpace(string(out))

	entries, err := ScanGitHistory(root, GitHistoryOptions{
		MaxCommits: 5,
		MaxFiles:   20,
	})
	if err != nil {
		t.Fatalf("ScanGitHistory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one file version in the CLI repo history")
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Key, PathGitHistoryPrefix) {
			t.Errorf("entry key %q missing %q prefix", e.Key, PathGitHistoryPrefix)
		}
		if e.Value == "" {
			// Empty values are OK for delete entries; if not a delete, that's
			// also acceptable for binary/symlink files we filtered out.
			continue
		}
		// Sanity: entries should be valid UTF-8 / printable text, otherwise
		// the secrets rules cannot match against them.
		if strings.ContainsAny(e.Value, "\x00") {
			t.Errorf("entry %q has NUL byte, likely a binary blob", e.Key)
		}
	}
}

// TestScanGitHistory_NoGitDir ensures the scanner quietly returns an empty
// result (and a nil error) for a non-repository path.
func TestScanGitHistory_NoGitDir(t *testing.T) {
	dir := t.TempDir()
	entries, err := ScanGitHistory(dir, GitHistoryOptions{})
	if err != nil {
		t.Fatalf("expected nil error for non-repo, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}
