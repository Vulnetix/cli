package web

import "net/http"

func Localised(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("Content-Language", r.URL.Query().Get("lang"))
~>	w.Header().Add("X-Request-Id",   r.FormValue("requestId"))
	w.WriteHeader(http.StatusOK)
}

func Track(rw http.ResponseWriter, req *http.Request) {
~>	rw.Header().Set(
		"X-Campaign",
		req.PostFormValue("campaign"),
	)
}
