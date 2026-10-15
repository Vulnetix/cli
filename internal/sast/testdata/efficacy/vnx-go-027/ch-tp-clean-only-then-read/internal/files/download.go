package files

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func (s *Service) Download(w http.ResponseWriter, r *http.Request) {
	requested := filepath.Clean(r.URL.Query().Get("name"))
	full := filepath.Join(s.baseDir, requested)
~>	f, err := os.Open(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

func (s *Service) Delete(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
~>	if err := os.Remove(s.baseDir + "/" + name); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
	}
}
