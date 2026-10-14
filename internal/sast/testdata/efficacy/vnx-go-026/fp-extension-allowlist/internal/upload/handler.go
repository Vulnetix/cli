package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var allowedExt = map[string]bool{".png": true, ".jpg": true, ".pdf": true}

func Upload(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, "no file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	ext := strings.ToLower(filepath.Ext(handler.Filename))
	if !allowedExt[ext] {
		http.Error(w, "file type not allowed", http.StatusUnsupportedMediaType)
		return
	}
	dst, err := os.Create(filepath.Join("./uploads", handler.Filename))
	if err != nil {
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}
