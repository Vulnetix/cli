package api

import (
	"io"
	"net/http"
	"os"
	"path"
)

func uploadDocs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return
	}
	for _, fh := range r.MultipartForm.File["documents"] {
		src, _ := fh.Open()
		data, _ := io.ReadAll(src)
		name := fh.Filename
		target := path.Join("static/docs", name)
~>		os.WriteFile(target, data, 0o644)
		src.Close()
	}
}
