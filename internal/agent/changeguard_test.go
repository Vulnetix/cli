package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyGitCommand(t *testing.T) {
	cases := []struct {
		name         string
		command      string
		wantKind     changeKind
		wantUnstaged bool
	}{
		{"plain commit", `git commit -m "wip"`, changeCommit, false},
		{"commit all long", `git commit --all -m "wip"`, changeCommit, true},
		{"commit all short", `git commit -am "wip"`, changeCommit, true},
		{"commit a separate", `git commit -a -m "wip"`, changeCommit, true},
		{"push", `git push origin main`, changePush, false},
		{"push force", `git push --force-with-lease`, changePush, false},

		// -C and other git-level options come before the subcommand, and a
		// classifier that assumed field[1] was the subcommand missed every one.
		{"dash C", `git -C /repo commit -m "wip"`, changeCommit, false},
		{"config override", `git -c user.name=x commit -m "wip"`, changeCommit, false},
		{"absolute git", `/usr/bin/git commit -m "wip"`, changeCommit, false},

		// The commit is the change; the push that follows carries it, so the
		// commit's own reading of the staged tree is the one that matters.
		{"commit then push", `git commit -m "wip" && git push`, changeCommit, false},

		// Everything a guard must not wake up for.
		{"status", `git status`, changeNone, false},
		{"log", `git log --oneline -5`, changeNone, false},
		{"add", `git add -A`, changeNone, false},
		{"diff", `git diff --cached`, changeNone, false},
		{"pull", `git pull --rebase`, changeNone, false},
		{"not git", `npm run commit`, changeNone, false},
		{"empty", ``, changeNone, false},
		{"bare git", `git`, changeNone, false},
		{"substring trap", `gitleaks detect`, changeNone, false},
		{"commit in a message", `echo "git commit"`, changeNone, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, unstaged := classifyGitCommand(tc.command)
			if kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", kind, tc.wantKind)
			}
			if unstaged != tc.wantUnstaged {
				t.Errorf("alsoUnstaged = %v, want %v", unstaged, tc.wantUnstaged)
			}
		})
	}
}

func TestIsGitCommitAllFlag(t *testing.T) {
	yes := []string{"-a", "-am", "-am", "-a", "--all", "-va"}
	no := []string{"-m", "--amend", "--allow-empty", "commit", "", "-S"}

	for _, f := range yes {
		if !isGitCommitAllFlag(f) {
			t.Errorf("%q should count as commit --all", f)
		}
	}
	for _, f := range no {
		if isGitCommitAllFlag(f) {
			// --amend and --allow-empty both start with "--all"-ish text or
			// contain an 'a'; neither stages anything, and treating them as -a
			// would make the guard read files the commit will not record.
			t.Errorf("%q should not count as commit --all", f)
		}
	}
}

// gitRepo builds a throwaway repository. Returns its root.
func gitRepo(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("init", "-q", "-b", "main")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	run("config", "commit.gpgsign", "false")

	return root
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	abs := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitIn(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func commitPayload(command string) Payload {
	return Payload{
		HookEventName: EventPreToolUse,
		ToolName:      "Bash",
		ToolInput:     []byte(`{"command":` + quote(command) + `}`),
	}
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// A staged AWS key is the case the guard exists for.
func TestChangeGuard_BlocksAStagedCredential(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "deploy.sh", "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	gitIn(t, root, "add", "deploy.sh")

	r := Runner{Policy: DefaultPolicy(), Root: root}
	got := r.Run(context.Background(), commitPayload(`git commit -m "deploy script"`))

	if got.Decision != Block {
		t.Fatalf("decision = %v, want Block\nmessage: %s", got.Decision, got.Message)
	}
	if !strings.Contains(got.Message, "deploy.sh") {
		t.Errorf("message should name the file:\n%s", got.Message)
	}
	if !strings.Contains(got.Message, "VNX-SEC-001") {
		t.Errorf("message should name the rule:\n%s", got.Message)
	}
	// A committed credential is disclosed whatever happens to the commit, and
	// saying so is the difference between a useful block and a speed bump.
	if !strings.Contains(got.Message, "rotating it") {
		t.Errorf("message should say the key needs rotating:\n%s", got.Message)
	}
}

// The ordinary commit. Silence is the whole point.
func TestChangeGuard_SilentOnACleanCommit(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "main.go", "package main\n\nfunc main() {}\n")
	gitIn(t, root, "add", "main.go")

	r := Runner{Policy: DefaultPolicy(), Root: root}
	got := r.Run(context.Background(), commitPayload(`git commit -m "hello"`))

	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent\nmessage: %s", got.Decision, got.Message)
	}
}

// A secret already in the repository is not something this commit is doing, and
// re-reporting it on every commit is how a guard gets switched off.
func TestChangeGuard_IgnoresAnUnstagedPreexistingSecret(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "old.sh", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	gitIn(t, root, "add", "old.sh")
	gitIn(t, root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "existing")

	write(t, root, "README.md", "# hello\n")
	gitIn(t, root, "add", "README.md")

	r := Runner{Policy: DefaultPolicy(), Root: root}
	got := r.Run(context.Background(), commitPayload(`git commit -m "docs"`))

	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent — the secret is not in this change\nmessage: %s",
			got.Decision, got.Message)
	}
}

// `git commit -a` records tracked modifications that were never staged, so a
// guard reading only the index would clear a change it had not looked at.
func TestChangeGuard_ReadsTheWorkingTreeForCommitAll(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "app.py", "print('hi')\n")
	gitIn(t, root, "add", "app.py")
	gitIn(t, root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "init")

	// Modified but deliberately not staged.
	write(t, root, "app.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

	r := Runner{Policy: DefaultPolicy(), Root: root}

	if got := r.Run(context.Background(), commitPayload(`git commit -m "x"`)); got.Decision != Silent {
		t.Fatalf("plain commit stages nothing here, so it should be silent: %v", got.Decision)
	}

	got := r.Run(context.Background(), commitPayload(`git commit -am "x"`))
	if got.Decision != Block {
		t.Fatalf("decision = %v, want Block for -a\nmessage: %s", got.Decision, got.Message)
	}
}

// Absence of an answer is not a verdict: the guard must never turn its own
// inability to look into a refusal.
func TestChangeGuard_SilentWhenItCannotLook(t *testing.T) {
	cases := []struct {
		name string
		root func(t *testing.T) string
	}{
		{"not a git repository", func(t *testing.T) string { return t.TempDir() }},
		{"no root at all", func(t *testing.T) string { return "" }},
		{"root does not exist", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "gone")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Runner{Policy: DefaultPolicy(), Root: tc.root(t)}
			got := r.Run(context.Background(), commitPayload(`git commit -m "x"`))
			if got.Decision != Silent {
				t.Fatalf("decision = %v, want Silent\nmessage: %s", got.Decision, got.Message)
			}
		})
	}
}

// A repository that demotes the signal gets a report instead of a refusal, and
// one that drops it entirely gets nothing.
func TestChangeGuard_HonoursThePolicy(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "deploy.sh", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	gitIn(t, root, "add", "deploy.sh")

	warn := DefaultPolicy()
	warn.ChangeGuard = GuardPolicy{Warn: []Signal{SignalSecret}}

	got := Runner{Policy: warn, Root: root}.
		Run(context.Background(), commitPayload(`git commit -m "x"`))
	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform", got.Decision)
	}
	if !strings.Contains(got.Message, "not blocked") {
		t.Errorf("a warning should say it did not block:\n%s", got.Message)
	}

	off := DefaultPolicy()
	off.ChangeGuard = GuardPolicy{Block: []Signal{SignalMalware}} // anything but secret

	got = Runner{Policy: off, Root: root}.
		Run(context.Background(), commitPayload(`git commit -m "x"`))
	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent when the policy does not ask about secrets", got.Decision)
	}
}

// The guard owns stdout only when it has something to say, and a block has to
// encode as a deny both hosts understand.
func TestChangeGuard_EncodesAsADeny(t *testing.T) {
	root := gitRepo(t)
	write(t, root, "deploy.sh", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	gitIn(t, root, "add", "deploy.sh")

	got := Runner{Policy: DefaultPolicy(), Root: root}.
		Run(context.Background(), commitPayload(`git commit -m "x"`))

	var out strings.Builder
	if err := got.Encode(&out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, `"permissionDecision":"deny"`) {
		t.Errorf("want a deny decision:\n%s", s)
	}
	if strings.Contains(s, `"permissionDecision":"allow"`) {
		t.Errorf("never emit allow — Codex fails the hook on it:\n%s", s)
	}
}
