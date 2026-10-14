package files

import (
	"net/http"
	"strings"
)

func Inline(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		http.NotFound(w, r)
		return
	}
~>	w.Header().Set("Content-Disposition", "inline; filename="+name)
	http.ServeFile(w, r, "/srv/blobs/current")
}

func Typed(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("Content-Type", r.URL.Query().Get("type"))
	w.Write([]byte("<svg/>"))
}
