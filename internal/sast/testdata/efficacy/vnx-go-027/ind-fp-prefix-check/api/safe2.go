package api

import (
	"net/http"
	"path/filepath"
	"strings"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	root := "/srv/files"
	full := filepath.Join(root, r.URL.Query().Get("f"))
	if !strings.HasPrefix(full, root+string(filepath.Separator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.ServeFile(w, r, full)
}
