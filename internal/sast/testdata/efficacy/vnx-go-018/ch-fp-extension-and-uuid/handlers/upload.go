package handlers

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("image")
	if err != nil {
		return
	}
	defer file.Close()
	ext := filepath.Ext(header.Filename)
	stored := uuid.NewString() + ext
	out, err := os.Create(filepath.Join("/srv/images", stored))
	if err != nil {
		return
	}
	defer out.Close()
	io.Copy(out, file)
}
