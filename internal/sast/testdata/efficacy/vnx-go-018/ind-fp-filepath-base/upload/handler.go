package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	safe := filepath.Join("/var/uploads", filepath.Base(r.FormValue("filename")))
	if err := os.WriteFile(safe, data, 0o600); err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
	}
}
