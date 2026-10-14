package scan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBinaryVersionIsRememberedPerFile(t *testing.T) {
	binaryVersionDir = t.TempDir()
	t.Cleanup(func() { binaryVersionDir = "" })
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	tool := filepath.Join(dir, "tool")
	write := func(version string) {
		script := "#!/bin/sh\necho x >> " + count + "\necho tool " + version + "\n"
		if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runs := func() int {
		b, _ := os.ReadFile(count)
		n := 0
		for _, c := range b {
			if c == '\n' {
				n++
			}
		}
		return n
	}

	write("1.2.3")
	for i := 0; i < 3; i++ {
		if v := binaryVersion(tool, tool, []string{"--version"}); v != "1.2.3" {
			t.Fatalf("version %q, want 1.2.3", v)
		}
	}
	if runs() != 1 {
		t.Fatalf("binary ran %d times for three lookups of the same file, want 1", runs())
	}

	// An upgrade is a different file: it is asked again.
	time.Sleep(10 * time.Millisecond)
	write("2.0.0")
	if v := binaryVersion(tool, tool, []string{"--version"}); v != "2.0.0" {
		t.Fatalf("after an upgrade the stale version %q was reused", v)
	}
}

func TestMain(m *testing.M) {
	// No test in this package may write the developer's real version store.
	binaryVersionDir = ""
	os.Exit(m.Run())
}
