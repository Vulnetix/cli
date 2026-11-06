package gitctx

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// unsetGitEnv drops the harness's GIT_* overrides (they point into a read-only
// admin dir and inject config, so every git write fails and repository lookups
// hit the wrong repository) from the test process; the code under test shells
// out to git and inherits it. Restored when the test ends.
func unsetGitEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		override := k == "GIT_DIR" || k == "GIT_WORK_TREE" || k == "GIT_COMMON_DIR" ||
			k == "GIT_OBJECT_DIRECTORY" || k == "GIT_ALTERNATE_OBJECT_DIRECTORIES" ||
			k == "GIT_INDEX_FILE" || k == "GIT_CONFIG_COUNT" ||
			strings.HasPrefix(k, "GIT_CONFIG_KEY_") || strings.HasPrefix(k, "GIT_CONFIG_VALUE_")
		if !override {
			continue
		}
		old, ok := os.LookupEnv(k)
		if !ok {
			continue
		}
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Setenv(k, old) })
	}
}

func TestConfigUserReadsRepoConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	unsetGitEnv(t)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
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
