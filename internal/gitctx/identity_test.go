package gitctx

import (
	"os/exec"
	"testing"
)

func TestConfigUserReadsRepoConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
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
