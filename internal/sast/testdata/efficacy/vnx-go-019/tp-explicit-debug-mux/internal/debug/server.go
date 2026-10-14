package debug

import (
	"expvar"
	"net/http"
	"net/http/pprof"
)

// The profiling handlers are mounted on their own mux, which is then bound to
// every interface.
func Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.Handle("/debug/vars", expvar.Handler())
~>	return http.ListenAndServe(":6060", mux)
}

func StartTLS(cert, key string) error {
	debugMux := http.NewServeMux()
	debugMux.HandleFunc("/debug/pprof/heap", pprof.Index)
	srv := &http.Server{
~>		Addr:    ":6443",
		Handler: debugMux,
	}
	return srv.ListenAndServeTLS(cert, key)
}
