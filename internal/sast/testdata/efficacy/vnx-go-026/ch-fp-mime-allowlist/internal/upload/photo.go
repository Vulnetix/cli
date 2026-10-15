package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

var allowedTypes = map[string]bool{"image/png": true, "image/jpeg": true}

func (h *Handler) Photo(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("photo")
	if err != nil {
		return
	}
	defer file.Close()
	head := make([]byte, 512)
	n, _ := file.Read(head)
	if !allowedTypes[http.DetectContentType(head[:n])] {
		http.Error(w, "unsupported file type", http.StatusUnsupportedMediaType)
		return
	}
	file.Seek(0, io.SeekStart)
	dst, _ := os.Create(filepath.Join(h.dir, filepath.Base(header.Filename)))
	defer dst.Close()
	io.Copy(dst, file)
}
