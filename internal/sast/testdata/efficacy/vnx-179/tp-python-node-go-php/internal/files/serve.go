package files

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.RawQuery
~>	if strings.Contains(raw, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	name, _ := url.QueryUnescape(raw)
	http.ServeFile(w, r, filepath.Join("/srv/files", name))
}
