package files

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (s *Service) Read(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	full := filepath.Join(s.root, name)
	if !strings.HasPrefix(full, s.root+string(os.PathSeparator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, _ := os.ReadFile(full)
	w.Write(data)
}

func Routes(mux *http.ServeMux) {
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
}
