package importer

import (
	"encoding/csv"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// The stored name is generated server-side; the client's name and extension
// never reach the filesystem.
func Store(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("data")
	if err != nil {
		return
	}
	defer file.Close()
	dst, err := os.Create(filepath.Join("/srv/blobs", uuid.NewString()))
	if err != nil {
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}

// Parsed in memory, never written.
func ImportCSV(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("csv")
	if err != nil {
		return
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil {
		http.Error(w, "bad csv in "+header.Filename, http.StatusBadRequest)
		return
	}
	_ = rows
}
