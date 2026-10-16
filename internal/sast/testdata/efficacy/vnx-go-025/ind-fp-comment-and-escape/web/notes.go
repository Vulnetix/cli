package web

import (
	"net/http"
	"net/url"
)

// Do not do: http.Redirect(w, r, r.URL.Query().Get("next"), 302)
func Search(w http.ResponseWriter, r *http.Request) {
	q := url.QueryEscape(r.URL.Query().Get("q"))
	http.Redirect(w, r, "/search?q="+q, http.StatusFound)
}
