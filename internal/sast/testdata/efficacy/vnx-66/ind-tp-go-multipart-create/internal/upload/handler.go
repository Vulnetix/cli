package upload

import (
	"io"
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

~>	dst, err := os.Create(filepath.Join("uploads", header.Filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	_, _ = io.Copy(dst, file)
	w.WriteHeader(http.StatusCreated)
}
