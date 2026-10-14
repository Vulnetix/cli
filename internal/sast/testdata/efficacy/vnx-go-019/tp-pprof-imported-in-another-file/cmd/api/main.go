package main

import (
	"log"
	"net"
	"net/http"
)

func main() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// The public port serves the default mux, so it serves pprof too.
~>	if err := http.ListenAndServe("0.0.0.0:8080", http.DefaultServeMux); err != nil {
		log.Fatal(err)
	}
}

func serveAdmin() error {
~>	ln, err := net.Listen("tcp", ":9090")
	if err != nil {
		return err
	}
	return http.Serve(ln, nil)
}
