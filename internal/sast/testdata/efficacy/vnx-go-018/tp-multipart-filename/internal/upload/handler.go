package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/lib/app/uploads"

// The client names the file; "../../etc/cron.d/x" lands outside uploadDir.
func Upload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer file.Close()
~>	dst, err := os.Create(filepath.Join(uploadDir, header.Filename))
	if err != nil {
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}

// The same through a variable, and every part of a multipart form.
func UploadMany(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return
	}
	for _, fh := range r.MultipartForm.File["docs"] {
		target := uploadDir + "/" + fh.Filename
		src, _ := fh.Open()
		data, _ := io.ReadAll(src)
~>		os.WriteFile(target, data, 0o644)
	}
}
