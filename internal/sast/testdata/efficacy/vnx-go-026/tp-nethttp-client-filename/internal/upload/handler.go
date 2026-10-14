package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// The client chooses the extension: shell.php or index.html lands in a
// directory the web server serves.
func Upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	file, handler, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, "no file", http.StatusBadRequest)
		return
	}
	defer file.Close()
~>	dst, err := os.Create(filepath.Join("./public/uploads", handler.Filename))
	if err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}
