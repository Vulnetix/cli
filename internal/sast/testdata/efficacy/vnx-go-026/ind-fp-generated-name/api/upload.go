package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()
	name := uuid.NewString() + ".bin"
	dst, err := os.Create(filepath.Join("/var/data/blobs", name))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}
