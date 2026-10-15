package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/srv/app/public/avatars"

func (h *Handler) Avatar(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()
~>	dst, err := os.Create(filepath.Join(uploadDir, header.Filename))
	if err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}
