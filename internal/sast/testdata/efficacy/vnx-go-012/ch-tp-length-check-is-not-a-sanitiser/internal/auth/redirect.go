package auth

import "net/http"

func AfterLogin(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	if len(next) == 0 {
		next = "/home"
	}
~>	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusSeeOther)
}

func Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cb := q.Get("callback")
	if cb == "" {
		cb = "handle"
	}
~>	w.Header().Set("X-JSONP-Callback", cb)
~>	w.Header().Set("X-Request-Tag", q.Get("tag"))
}
