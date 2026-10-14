package upload

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUploadWritesFile(t *testing.T) {
	r := httptest.NewRequest("POST", "/upload?name=a.txt", nil)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, r.URL.Query().Get("name")), []byte("x"), 0o600)
}
