package testutils

import (
	"os"
	"strings"
	"testing"
)

// gitConfigIsolation is the environment that keeps a git process away from
// the user's and the system's config files, so a test sees only the
// repository it builds.
var gitConfigIsolation = []string{
	"GIT_CONFIG_NOSYSTEM=1",
	"GIT_CONFIG_GLOBAL=/dev/null",
	"GIT_CONFIG_SYSTEM=/dev/null",
}

// gitRepoOverride reports whether k is an environment variable that points
// git at a repository, an object store or injected config other than the one
// a test builds. A runner that exports them (a sandbox's GIT_DIR into a
// read-only admin dir, a hook's GIT_INDEX_FILE) makes every git a test spawns
// operate on the wrong repository or fail to lock its config.
func gitRepoOverride(k string) bool {
	switch k {
	case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT":
		return true
	}
	return strings.HasPrefix(k, "GIT_CONFIG_KEY_") || strings.HasPrefix(k, "GIT_CONFIG_VALUE_")
}

// HermeticGit makes the current test independent of the git environment it
// inherited: the repository overrides are removed from the process for the
// duration of the test (restored on cleanup) and global and system config are
// neutralised. Use it when the code under test shells out to git, or reads a
// repository with go-git, and so inherits the process environment. Tests that
// call it must not run in parallel.
func HermeticGit(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, old, _ := strings.Cut(kv, "=")
		if !gitRepoOverride(k) {
			continue
		}
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Setenv(k, old) })
	}
	for _, kv := range gitConfigIsolation {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
}

// GitChildEnv returns an environment for a git child process with the
// repository overrides dropped and global and system config neutralised,
// followed by extra (for example GIT_AUTHOR_NAME=t).
func GitChildEnv(extra ...string) []string {
	parent := os.Environ()
	env := make([]string, 0, len(parent)+len(gitConfigIsolation)+len(extra))
	for _, kv := range parent {
		k, _, _ := strings.Cut(kv, "=")
		if gitRepoOverride(k) || k == "GIT_CONFIG_NOSYSTEM" || k == "GIT_CONFIG_GLOBAL" || k == "GIT_CONFIG_SYSTEM" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, gitConfigIsolation...)
	return append(env, extra...)
}
