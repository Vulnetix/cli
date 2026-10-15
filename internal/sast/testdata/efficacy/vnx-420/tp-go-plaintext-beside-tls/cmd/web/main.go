package main

import (
	"log"
	"net/http"
)

func main() {
	mux := routes()
	go func() {
~>		log.Fatal(http.ListenAndServe(":8080", mux))
	}()
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", mux))
}
