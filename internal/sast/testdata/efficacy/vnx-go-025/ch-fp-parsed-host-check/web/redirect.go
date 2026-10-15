package web

import (
	"net/http"
	"net/url"
)

func SafeNext(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("next")
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, u.Path, http.StatusFound)
}

func Canonical(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+cfg.PublicHost+"/login", http.StatusMovedPermanently)
}
