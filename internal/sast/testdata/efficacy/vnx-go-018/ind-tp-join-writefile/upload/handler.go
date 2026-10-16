package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	filename := r.FormValue("filename")
	path := filepath.Join("/var/uploads", filename)
~>	if err := os.WriteFile(path, data, 0o644); err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
	}
}
