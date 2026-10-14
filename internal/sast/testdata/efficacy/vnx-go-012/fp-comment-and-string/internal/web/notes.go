package web

import "net/http"

// Do not write w.Header().Set("X-Lang", r.URL.Query().Get("lang")): validate first.
const bad = `w.Header().Set("X-Lang", r.FormValue("lang"))`

func Notes(w http.ResponseWriter, r *http.Request) {
	// w.Header().Add("X-Debug", r.FormValue("debug"))
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(bad))
}
