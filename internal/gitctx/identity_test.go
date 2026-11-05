package gitctx

import (
	"os/exec"
	"testing"

	"github.com/vulnetix/cli/v4/internal/testutils"
)

func TestConfigUserReadsRepoConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	testutils.HermeticGit(t)
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.name", "Ada Lovelace")
	run("config", "user.email", "ada@example.com")

	got := ConfigUser(dir)
	if got.Name != "Ada Lovelace" || got.Email != "ada@example.com" {
		t.Fatalf("ConfigUser = %+v", got)
	}
	if a := LocalActor(dir); a != "ada@example.com" {
		t.Fatalf("LocalActor = %q, want the git config email", a)
	}
}

func TestConfigUserToleratesNoRepo(t *testing.T) {
	// A directory that does not exist makes `git -C` fail; that must read as
	// "no identity", not an error.
	got := ConfigUser(t.TempDir() + "/missing")
	if got.Name != "" || got.Email != "" {
		t.Fatalf("ConfigUser outside a repo = %+v, want empty", got)
	}
}

func TestOSActor(t *testing.T) {
	cases := []struct {
		sys  *SystemInfo
		want string
	}{
		{nil, ""},
		{&SystemInfo{}, ""},
		{&SystemInfo{Username: "ci"}, "ci"},
		{&SystemInfo{Username: "ci", Hostname: "runner-1"}, "ci@runner-1"},
	}
	for _, c := range cases {
		if got := osActor(c.sys); got != c.want {
			t.Errorf("osActor(%+v) = %q, want %q", c.sys, got, c.want)
		}
	}
}

// LocalActor falls back to osActor (user@host) when git config has no email,
// and the git config email wins when it is set. ConfigUser caches per
// directory, so every case gets its own directory.
func TestLocalActorConfigAndFallback(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	testutils.HermeticGit(t)

	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// Empty config email falls through to osActor's user@host.
	noEmail := t.TempDir()
	run(noEmail, "init", "-q")
	run(noEmail, "config", "user.name", "Ada Lovelace")
	info := CollectSystemInfo()
	want := info.Username
	if info.Hostname != "" {
		want += "@" + info.Hostname
	}
	if got := LocalActor(noEmail); got != want {
		t.Errorf("LocalActor without an email = %q, want %q", got, want)
	}

	// A set email wins over the fallback.
	withEmail := t.TempDir()
	run(withEmail, "init", "-q")
	run(withEmail, "config", "user.name", "Ada Lovelace")
	run(withEmail, "config", "user.email", "ada@example.com")
	if got := LocalActor(withEmail); got != "ada@example.com" {
		t.Errorf("LocalActor with an email = %q, want ada@example.com", got)
	}
}
