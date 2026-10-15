package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func serveDoc(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("doc")
~>	name = strings.ReplaceAll(name, "../", "")
	b, _ := os.ReadFile(filepath.Join("/srv/docs", name))
	w.Write(b)
}

func serveImg(w http.ResponseWriter, r *http.Request) {
~>	name := strings.Replace(r.URL.Query().Get("img"), "..", "", -1)
	http.ServeFile(w, r, "/srv/img/"+name)
}
