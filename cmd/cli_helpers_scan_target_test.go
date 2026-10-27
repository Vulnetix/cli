package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A scan's cli.* requests describe the scanned repository, not the directory
// the CLI was started in.
func TestCliRequestsCarryTheScanTargetRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Cleanup(func() { scanTargetDir.Store(nil) })

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	scanTargetDir.Store(nil)
	if got := cliGitDir(); got != cwd {
		t.Fatalf("with no scan target, cliGitDir() = %q, want the working directory %q", got, cwd)
	}

	target := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "scan-target-branch"},
		{"-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "init"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", target}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	setScanTarget(target)
	if got := cliGitDir(); got != target {
		t.Fatalf("cliGitDir() = %q, want the scan target %q", got, target)
	}

	env := envForCli()
	if env.Git == nil {
		t.Fatal("envForCli() carried no git context for the scan target")
	}
	if env.Git.Branch != "scan-target-branch" {
		t.Errorf("Git.Branch = %q, want the scan target's branch", env.Git.Branch)
	}
	if root, _ := filepath.EvalSymlinks(env.Git.RepoRoot); root != mustEvalSymlinks(t, target) {
		t.Errorf("Git.RepoRoot = %q, want the scan target %q", env.Git.RepoRoot, target)
	}
	// The scan's own context and the requests' are one collection.
	first, second := cwdGitContext(target), cwdGitContext(target)
	if first != second {
		t.Error("cwdGitContext collected the scan target twice")
	}
}

func mustEvalSymlinks(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
