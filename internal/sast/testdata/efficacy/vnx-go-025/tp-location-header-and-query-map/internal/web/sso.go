package web

import "net/http"

func ssoCallback(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("Location", r.URL.Query().Get("RelayState"))
	w.WriteHeader(http.StatusFound)
}

func shortLink(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	recordClick(q.Get("id"))
~>	http.Redirect(w, r, q.Get("u"), http.StatusFound)
}

func recordClick(string) {}
