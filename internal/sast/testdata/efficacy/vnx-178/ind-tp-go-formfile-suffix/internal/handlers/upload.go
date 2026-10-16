package handlers

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

~>	if strings.HasSuffix(header.Filename, ".php") || strings.HasSuffix(header.Filename, ".sh") {
		http.Error(w, "forbidden file type", http.StatusForbidden)
		return
	}

	dst, err := os.Create(filepath.Join("static/uploads", filepath.Base(header.Filename)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}
