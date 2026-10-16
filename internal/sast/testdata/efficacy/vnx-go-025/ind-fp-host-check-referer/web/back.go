package web

import (
	"net/http"
	"net/url"
)

func Go(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("url")
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u.Path, http.StatusFound)
}

func Back(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}
