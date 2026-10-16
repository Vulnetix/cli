package web

import (
	"net/http"
	"os"
)

var pages = map[string]string{"about": "/srv/about.html", "help": "/srv/help.html"}

func Page(w http.ResponseWriter, r *http.Request) {
	p, ok := pages[r.URL.Query().Get("p")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, _ := os.ReadFile(p)
	w.Write(data)
}
