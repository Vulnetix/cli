package auth

import (
	"net/http"
	"net/url"
)

// url.Parse rejects control characters, and the host check keeps the
// redirect on this site.
func AfterLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" {
		next = "/"
	}
	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusSeeOther)
}
