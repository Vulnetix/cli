package web

import "net/http"

func Go(w http.ResponseWriter, r *http.Request) {
~>	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}
