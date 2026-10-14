package gitctx

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
)

func TestGitStatusDirtyAgreesWithGoGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.email=t@t", "-c", "user.name=t"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q")
	write(".gitignore", "ignored.txt\n")
	write("a.txt", "a")
	run("add", ".")
	run("commit", "-qm", "init")

	goGitDirty := func() bool {
		repo, err := git.PlainOpen(root)
		if err != nil {
			t.Fatal(err)
		}
		wt, _ := repo.Worktree()
		st, err := wt.Status()
		if err != nil {
			t.Fatal(err)
		}
		return !st.IsClean()
	}
	check := func(state string, want bool) {
		t.Helper()
		got, ok := gitStatusDirty(root)
		if !ok {
			t.Fatalf("%s: git status failed", state)
		}
		if got != want || goGitDirty() != want {
			t.Fatalf("%s: git says dirty=%v, go-git says %v, want %v", state, got, goGitDirty(), want)
		}
	}
	check("clean", false)
	write("ignored.txt", "x")
	check("only an ignored file", false)
	write("new.txt", "x")
	check("untracked file", true)
	os.Remove(filepath.Join(root, "new.txt"))
	write("a.txt", "changed")
	check("modified file", true)
}
