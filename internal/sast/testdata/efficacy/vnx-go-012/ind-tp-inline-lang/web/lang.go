package web

import "net/http"

func Localised(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("Content-Language", r.URL.Query().Get("lang"))
	w.Write([]byte("ok"))
}
