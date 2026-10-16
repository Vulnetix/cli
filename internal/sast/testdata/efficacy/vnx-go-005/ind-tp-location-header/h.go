package web

import "net/http"

func Hdr(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("Location", r.URL.Query().Get("to"))
	w.WriteHeader(http.StatusFound)
}
