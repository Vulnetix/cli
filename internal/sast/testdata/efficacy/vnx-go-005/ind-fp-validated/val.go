package web

import (
	"net/http"
	"net/url"
)

func Next(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("next")
	u, err := url.Parse(raw)
	if err != nil || u.Host != "" || u.Scheme != "" {
		raw = "/"
	}
	_ = raw
	http.Redirect(w, r, "/", http.StatusFound)
}
