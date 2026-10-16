package upload

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const uploadDir = "/var/uploads"

func Handler(w http.ResponseWriter, r *http.Request) {
	cleaned := filepath.Clean(filepath.Join(uploadDir, r.FormValue("filename")))
	if !strings.HasPrefix(cleaned, uploadDir+string(filepath.Separator)) {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}
	os.WriteFile(cleaned, []byte("x"), 0o600)
}
