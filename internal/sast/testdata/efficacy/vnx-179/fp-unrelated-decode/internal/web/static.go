package web

import (
	"net/http"
	"net/url"
	"strings"
)

func Static(w http.ResponseWriter, r *http.Request) {
	p, err := url.PathUnescape(r.URL.EscapedPath())
	if err != nil || strings.Contains(p, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	http.ServeFile(w, r, "/srv"+p)
}
