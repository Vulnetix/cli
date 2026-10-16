package web

import "net/http"

func Next(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
~>	http.Redirect(w, r, target, http.StatusFound)
}
