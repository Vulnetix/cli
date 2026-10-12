package secretscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// A shallow clone ends at a commit whose parent is not in the object store. Every GitHub
// Actions checkout is one, and a worktree of it shares the same boundary, so the history scan
// has to read what exists and stop rather than fail with "object not found".
func TestScanGitHistory_ShallowCloneAndItsWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	origin := t.TempDir()
	git(origin, "init", "-q", "-b", "main")
	for i, body := range []string{"one\n", "two\n", "three\n"} {
		name := filepath.Join(origin, "f.txt")
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		git(origin, "add", ".")
		git(origin, "commit", "-q", "-m", "commit "+strconv.Itoa(i))
	}

	clone := filepath.Join(t.TempDir(), "clone")
	git(filepath.Dir(clone), "clone", "-q", "--depth", "1", "file://"+origin, clone)
	worktree := filepath.Join(clone, ".claude", "worktrees", "feature")
	git(clone, "worktree", "add", "-q", "--detach", worktree, "HEAD")

	for name, dir := range map[string]string{"shallow clone": clone, "worktree of it": worktree} {
		entries, err := ScanGitHistory(dir, GitHistoryOptions{MaxCommits: 5, MaxFiles: 20})
		if err != nil {
			t.Fatalf("%s: ScanGitHistory: %v", name, err)
		}
		if len(entries) == 0 {
			t.Errorf("%s: expected the one commit that exists to be read", name)
		}
	}
}
