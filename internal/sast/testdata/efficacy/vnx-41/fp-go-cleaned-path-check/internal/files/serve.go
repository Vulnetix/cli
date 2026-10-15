package files

import (
	"net/http"
	"path/filepath"
	"strings"
)

const rootDir = "/srv/files"

func Serve(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(rootDir, r.URL.Query().Get("name"))
	if !strings.HasPrefix(p, rootDir+string(filepath.Separator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	q := filepath.Clean(rootDir + "/" + r.FormValue("q"))
	if strings.HasPrefix(q, rootDir) {
		http.ServeFile(w, r, q)
	}
}
