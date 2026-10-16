package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	file, handler, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()
~>	dst, err := os.Create(filepath.Join("./public/uploads", handler.Filename))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}
