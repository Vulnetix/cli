package files

import (
	"net/http"
	"path/filepath"
	"strings"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
~>	name = strings.ReplaceAll(name, "../", "")
	http.ServeFile(w, r, filepath.Join("/var/www/files", name))
}
