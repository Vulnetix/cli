package testutils

import (
	"os"
	"testing"
)

func TestSetEnvRestores(t *testing.T) {
	const keepKey = "TESTUTILS_SETENV_KEEP"
	const unsetKey = "TESTUTILS_SETENV_UNSET"

	t.Setenv(keepKey, "original")
	// t.Setenv registers the restore of the real original; the Unsetenv makes
	// the variable genuinely unset, not merely empty, for SetEnv to observe.
	t.Setenv(unsetKey, "")
	if err := os.Unsetenv(unsetKey); err != nil {
		t.Fatalf("Unsetenv(%s): %v", unsetKey, err)
	}

	restore := SetEnv(t, map[string]string{
		keepKey:  "changed",
		unsetKey: "changed",
	})

	if got := os.Getenv(keepKey); got != "changed" {
		t.Fatalf("after SetEnv, %s = %q, want %q", keepKey, got, "changed")
	}
	if got := os.Getenv(unsetKey); got != "changed" {
		t.Fatalf("after SetEnv, %s = %q, want %q", unsetKey, got, "changed")
	}

	restore()

	if got := os.Getenv(keepKey); got != "original" {
		t.Fatalf("after restore, %s = %q, want %q", keepKey, got, "original")
	}
	if _, ok := os.LookupEnv(unsetKey); ok {
		t.Fatalf("after restore, %s should be unset", unsetKey)
	}
}

func TestClearEnvRestores(t *testing.T) {
	const keepKey = "TESTUTILS_CLEARENV_KEEP"
	const emptyKey = "TESTUTILS_CLEARENV_EMPTY"

	// t.Setenv restores whatever these held before the test, so the test
	// never clobbers a value that existed outside it.
	t.Setenv(keepKey, "original")
	t.Setenv(emptyKey, "")
	if err := os.Unsetenv(emptyKey); err != nil {
		t.Fatalf("Unsetenv(%s): %v", emptyKey, err)
	}

	restore := ClearEnv(t, []string{keepKey, emptyKey})

	if _, ok := os.LookupEnv(keepKey); ok {
		t.Fatalf("after ClearEnv, %s should be unset", keepKey)
	}

	restore()

	if got := os.Getenv(keepKey); got != "original" {
		t.Fatalf("after restore, %s = %q, want %q", keepKey, got, "original")
	}
	if _, ok := os.LookupEnv(emptyKey); ok {
		t.Fatalf("after restore, %s should remain unset", emptyKey)
	}
}
