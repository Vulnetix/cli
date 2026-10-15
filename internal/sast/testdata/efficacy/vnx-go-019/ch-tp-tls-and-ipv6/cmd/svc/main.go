package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	go func() {
~>		log.Println(http.ListenAndServe("[::]:6060", nil))
	}()
	srv := &http.Server{
~>		Addr:    ":8443",
		Handler: http.DefaultServeMux,
	}
	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
}
