package static

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const root = "/srv/static"

func Serve(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(root, r.URL.Query().Get("f"))
	if !strings.HasPrefix(p, root+string(os.PathSeparator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.ServeFile(w, r, p)
}

func isAPI(r *http.Request) bool {
	route := "/" + strings.TrimPrefix(r.URL.Path, "/")
	return strings.HasPrefix(route, "/api/")
}
