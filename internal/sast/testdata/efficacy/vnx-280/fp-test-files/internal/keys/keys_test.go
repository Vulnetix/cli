package keys

import (
	"os"
	"testing"
)

func TestSave(t *testing.T) {
	p := t.TempDir() + "/key"
	os.WriteFile(p, []byte("x"), 0o644)
	os.Chmod(p, 0600)
}
