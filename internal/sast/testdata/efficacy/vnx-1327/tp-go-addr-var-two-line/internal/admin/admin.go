package admin

import "net/http"

func Start(mux *http.ServeMux) error {
	addr := "0.0.0.0:6060"
~>	return http.ListenAndServe(addr, mux)
}
