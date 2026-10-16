package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	id := uuid.New().String()
	if err := os.WriteFile(filepath.Join("/var/uploads", id), data, 0o600); err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	recordName(id, r.FormValue("filename"))
}

func recordName(id, name string) {}
