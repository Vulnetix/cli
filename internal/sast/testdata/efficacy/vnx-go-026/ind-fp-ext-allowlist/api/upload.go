package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()
	switch strings.ToLower(filepath.Ext(handler.Filename)) {
	case ".png", ".jpg", ".pdf":
	default:
		http.Error(w, "type not allowed", http.StatusUnsupportedMediaType)
		return
	}
	dst, _ := os.Create(filepath.Join("./uploads", filepath.Base(handler.Filename)))
	defer dst.Close()
	io.Copy(dst, file)
}
