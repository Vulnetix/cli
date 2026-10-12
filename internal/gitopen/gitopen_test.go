package gitopen

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
)

func run(t *testing.T, dir string, args ...string) {
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

// A worktree's objects live in the main repository's git dir. go-git follows the `.git` file
// to the worktree's private dir but not on to that shared object store unless asked to, so the
// repository opens and then every commit lookup fails with "object not found".
func TestOpenReadsHistoryInAWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	main := t.TempDir()
	run(t, main, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(main, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, main, "add", ".")
	run(t, main, "commit", "-q", "-m", "first")

	// Nested under the main checkout, as `.claude/worktrees/<name>` is.
	wt := filepath.Join(main, ".claude", "worktrees", "feature")
	run(t, main, "worktree", "add", "-q", "--detach", wt, "HEAD")

	if info, err := os.Stat(filepath.Join(wt, ".git")); err != nil || info.IsDir() {
		t.Fatalf("expected %s/.git to be a file", wt)
	}

	for _, detect := range []bool{false, true} {
		repo, err := Open(wt, detect)
		if err != nil {
			t.Fatalf("Open(detectParents=%v): %v", detect, err)
		}
		head, err := repo.Head()
		if err != nil {
			t.Fatalf("Head: %v", err)
		}
		if _, err := repo.CommitObject(head.Hash()); err != nil {
			t.Errorf("detectParents=%v: reading the commit in a worktree failed: %v", detect, err)
		}
	}

	// Pins why this package exists: the stock open succeeds and then cannot read a commit.
	plain, err := git.PlainOpen(wt)
	if err != nil {
		t.Skipf("go-git now rejects a plain open of a worktree outright: %v", err)
	}
	if head, herr := plain.Head(); herr == nil {
		if _, cerr := plain.CommitObject(head.Hash()); cerr == nil {
			t.Error("plain PlainOpen read a worktree's commit; gitopen may no longer be needed")
		}
	}
}

func TestOpenDetectParentsOnlyWhenAsked(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	run(t, root, "init", "-q")
	sub := filepath.Join(root, "pkg", "x")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(sub, false); err == nil {
		t.Error("a subdirectory must not open as a repository when detectParents is false")
	}
	if _, err := Open(sub, true); err != nil {
		t.Errorf("a subdirectory should resolve to its repository with detectParents: %v", err)
	}
}
