package testutils

import (
	"os"
	"testing"
)

func TestSetEnvRestores(t *testing.T) {
	const keepKey = "TESTUTILS_SETENV_KEEP"
	const unsetKey = "TESTUTILS_SETENV_UNSET"

	t.Setenv(keepKey, "original")
	t.Setenv(unsetKey, "")

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

	os.Setenv(keepKey, "original")
	os.Unsetenv(emptyKey)
	t.Cleanup(func() {
		os.Unsetenv(keepKey)
	})

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
