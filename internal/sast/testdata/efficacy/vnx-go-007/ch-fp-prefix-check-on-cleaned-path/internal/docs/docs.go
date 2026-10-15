package docs

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const base = "/srv/docs"

func Page(w http.ResponseWriter, r *http.Request) {
	full := filepath.Clean(filepath.Join(base, r.URL.Query().Get("page")))
	if !strings.HasPrefix(full, base+string(os.PathSeparator)) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
