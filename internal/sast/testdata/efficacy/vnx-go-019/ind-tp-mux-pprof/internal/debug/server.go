package debug

import (
	"net/http"
	"net/http/pprof"
)

func Serve() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
~>	return http.ListenAndServe(":6060", mux)
}
