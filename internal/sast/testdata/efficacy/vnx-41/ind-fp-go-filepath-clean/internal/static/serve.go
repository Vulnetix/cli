package static

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const rootDir = "/srv/static"

func Serve(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(rootDir, r.URL.Query().Get("file"))
	if !strings.HasPrefix(p, rootDir+string(os.PathSeparator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	q := filepath.Clean(rootDir + "/" + r.URL.Query().Get("other"))
	if !strings.HasPrefix(q, rootDir) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}
