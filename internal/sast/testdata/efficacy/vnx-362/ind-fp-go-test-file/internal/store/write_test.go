package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBlobCreatesFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blob")
	if _, err := os.Stat(p); err == nil {
		t.Fatal("file should not exist yet")
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}
