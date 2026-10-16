package upload

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	log.Printf("upload %s (%d bytes)", header.Filename, header.Size)

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(data)
	name := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join("uploads", name), data, 0o640); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
