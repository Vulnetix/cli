package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	srv := &http.Server{
		Addr:    ":8443",
		Handler: mux,
		TLSConfig: &tls.Config{
~>			MinVersion: tls.VersionTLS10,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
}
