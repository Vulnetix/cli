package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// Regressions from the second efficacy sweep. Each of these was found by
// running the shipped binary against a case the first suite had not imagined,
// and each was silent where it should have spoken, or spoke where it should
// have been silent.

// A rename whose new content adds a secret. `--diff-filter=ACM` excludes R, so
// `git mv a.sh b.sh` plus a credential on the end went unread.
func TestChangeGuard_ReadsARenamedFile(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "a.sh", "echo hi\n# 1\n# 2\n# 3\n# 4\n")
	gitIn(t, root, "add", "a.sh")
	gitIn(t, root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "seed")

	gitIn(t, root, "mv", "a.sh", "b.sh")
	write(t, root, "b.sh", "echo hi\n# 1\n# 2\n# 3\n# 4\nKEY=AKIAIOSFODNN7EXAMPLE\n")
	gitIn(t, root, "add", "-A")

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), commitPayload(`git commit -m mv`))
	if got.Decision != Block {
		t.Fatalf("decision = %v, want Block for a rename carrying a secret\n%s", got.Decision, got.Message)
	}
}

// Over the file cap with the secret in the part that was not read: the guard
// must say it stopped, not imply a clean bill.
func TestChangeGuard_SaysSoWhenItStopsAtTheCap(t *testing.T) {
	root := gitRepo(t)
	for i := 0; i < changeGuardMaxFiles; i++ {
		write(t, root, fmt.Sprintf("f%04d.txt", i), "x\n")
	}
	write(t, root, "zzz.sh", "KEY=AKIAIOSFODNN7EXAMPLE\n")
	gitIn(t, root, "add", "-A")

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), commitPayload(`git commit -m big`))
	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform when the cap was hit\n%s", got.Decision, got.Message)
	}
	if !strings.Contains(got.Message, "stopped at its cap") || !strings.Contains(got.Message, "not checked") {
		t.Errorf("message must say the change was only partly read:\n%s", got.Message)
	}
}

// `git commit -a` typed in a subdirectory. Paths from git are repository
// relative; joining them onto the subdirectory produced a file that did not
// exist, and the modified file the commit was about to record went unread.
func TestChangeGuard_CommitAllFromASubdirectory(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "pkg/sub/app.py", "v1\n")
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "seed")
	write(t, root, "pkg/sub/app.py", "KEY=AKIAIOSFODNN7EXAMPLE\n") // modified, unstaged

	sub := filepath.Join(root, "pkg", "sub")
	got := Runner{Policy: DefaultPolicy(), Root: sub}.
		Run(context.Background(), commitPayload(`git commit -am x`))
	if got.Decision != Block {
		t.Fatalf("decision = %v, want Block from a subdirectory\n%s", got.Decision, got.Message)
	}
}

// `git -C dir commit` from an unrelated cwd operates on dir.
func TestChangeGuard_HonoursDashC(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "s.sh", "KEY=AKIAIOSFODNN7EXAMPLE\n")
	gitIn(t, root, "add", "-A")

	elsewhere := t.TempDir()
	for _, form := range []string{
		fmt.Sprintf(`git -C %s commit -m x`, root),
		fmt.Sprintf(`git -C%s commit -m x`, root),
		fmt.Sprintf(`git -C "%s" commit -m x`, root),
	} {
		got := Runner{Policy: DefaultPolicy(), Root: elsewhere}.
			Run(context.Background(), commitPayload(form))
		if got.Decision != Block {
			t.Errorf("%q: decision = %v, want Block", form, got.Decision)
		}
	}
}

func TestGitChangeDir(t *testing.T) {
	cases := map[string]string{
		`git -C /r commit -m x`:       "/r",
		`git -C/r commit -m x`:        "/r",
		`git -C "my dir" commit`:      "my dir",
		`git -c a=b -C /r push`:       "/r",
		`git commit -m "-C not here"`: "",
		`git status`:                  "",
		`gitleaks -C /r detect`:       "",
	}
	for cmd, want := range cases {
		if got := gitChangeDir(cmd); got != want {
			t.Errorf("gitChangeDir(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// The malware verdict on a bare name is a fact about the package's history.
// express has one compromised release on the OSS malicious-packages list, so
// `pkg:npm/express` comes back malicious while every current release is clean.
// Unresolved, that must inform; resolved to a malicious release, it must block.
func TestDependencyGuard_NameLevelMalwareInformsResolvedMalwareBlocks(t *testing.T) {
	mal := &vdb.CliPackageInsight{Name: "express", Ecosystem: "npm", IsMalicious: true}

	unresolved := EvaluateDependency(DefaultPolicy(), []Assessment{{
		Candidate: Candidate{Name: "express", Ecosystem: "npm"},
		Insight:   mal,
		NameLevel: true,
	}})
	if unresolved.Decision != Inform {
		t.Fatalf("name-level malware: decision = %v, want Inform\n%s", unresolved.Decision, unresolved.Message)
	}
	if !strings.Contains(unresolved.Message, "About the name, not a release") {
		t.Errorf("message must say the verdict is about the name:\n%s", unresolved.Message)
	}

	resolved := EvaluateDependency(DefaultPolicy(), []Assessment{{
		Candidate: Candidate{Name: "evil-pkg", Ecosystem: "npm"},
		Resolved:  "1.0.3",
		Insight:   &vdb.CliPackageInsight{Name: "evil-pkg", Ecosystem: "npm", Version: "1.0.3", IsMalicious: true},
	}})
	if resolved.Decision != Block {
		t.Fatalf("resolved malicious release: decision = %v, want Block\n%s", resolved.Decision, resolved.Message)
	}
}

// The policy can still be told to block name-level malware if a repository
// wants that, and the default warns rather than blocks.
func TestPolicy_MalwareUnresolvedIsWarnByDefault(t *testing.T) {
	p := DefaultPolicy()
	if p.DependencyGuard.Decide(SignalMalwareUnresolved) != Inform {
		t.Fatal("malware-unresolved should inform by default")
	}
	if p.DependencyGuard.Decide(SignalMalware) != Block {
		t.Fatal("malware should still block by default")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".vulnetix"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".vulnetix", "agent.yaml"),
		[]byte("agent:\n  dependencyGuard:\n    block: [malware, malware-unresolved]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	strict, err := LoadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if strict.DependencyGuard.Decide(SignalMalwareUnresolved) != Block {
		t.Fatal("a repository that opts in should be able to block name-level malware")
	}
}
