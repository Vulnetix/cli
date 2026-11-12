package testutils

import (
	"os"
	"slices"
	"testing"
)

func TestHermeticGitDropsOverridesAndRestoresThem(t *testing.T) {
	t.Run("scrubbed", func(t *testing.T) {
		t.Setenv("GIT_DIR", "/nonexistent/admin")
		t.Setenv("GIT_CONFIG_KEY_0", "user.name")
		t.Setenv("GIT_AUTHOR_NAME", "kept")

		t.Run("inner", func(t *testing.T) {
			HermeticGit(t)
			if _, ok := os.LookupEnv("GIT_DIR"); ok {
				t.Error("GIT_DIR still set")
			}
			if _, ok := os.LookupEnv("GIT_CONFIG_KEY_0"); ok {
				t.Error("GIT_CONFIG_KEY_0 still set")
			}
			if got := os.Getenv("GIT_AUTHOR_NAME"); got != "kept" {
				t.Errorf("GIT_AUTHOR_NAME = %q, want kept", got)
			}
			if got := os.Getenv("GIT_CONFIG_GLOBAL"); got != "/dev/null" {
				t.Errorf("GIT_CONFIG_GLOBAL = %q, want /dev/null", got)
			}
		})

		if got := os.Getenv("GIT_DIR"); got != "/nonexistent/admin" {
			t.Errorf("GIT_DIR not restored: %q", got)
		}
	})
}

func TestGitChildEnv(t *testing.T) {
	t.Setenv("GIT_DIR", "/nonexistent/admin")
	t.Setenv("GIT_INDEX_FILE", "/nonexistent/index")
	t.Setenv("GIT_CONFIG_GLOBAL", "/home/someone/.gitconfig")
	t.Setenv("GIT_AUTHOR_NAME", "kept")

	env := GitChildEnv("GIT_COMMITTER_NAME=t")
	for _, gone := range []string{"GIT_DIR=/nonexistent/admin", "GIT_INDEX_FILE=/nonexistent/index", "GIT_CONFIG_GLOBAL=/home/someone/.gitconfig"} {
		if slices.Contains(env, gone) {
			t.Errorf("%s still in child env", gone)
		}
	}
	for _, want := range []string{"GIT_AUTHOR_NAME=kept", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_COMMITTER_NAME=t"} {
		if !slices.Contains(env, want) {
			t.Errorf("%s missing from child env", want)
		}
	}
	if env[len(env)-1] != "GIT_COMMITTER_NAME=t" {
		t.Errorf("extra not last: %q", env[len(env)-1])
	}
}
