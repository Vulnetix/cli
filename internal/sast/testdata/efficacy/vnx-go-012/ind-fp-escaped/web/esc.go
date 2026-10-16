package web

import (
	"net/http"
	"net/url"
)

func Download(w http.ResponseWriter, r *http.Request) {
	name := url.QueryEscape(r.URL.Query().Get("name"))
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Header().Set("X-Request-Q", url.PathEscape(r.FormValue("q")))
}
