package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadToken(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("abc"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadToken(dir)
	if err != nil || string(got) != "abc" {
		t.Fatalf("got %q, %v", got, err)
	}
}
