package main

import (
	"log"
	"net/http"
)

func main() {
	router := newRouter()
	go func() {
~>		log.Println(http.ListenAndServe(":8080", router))
	}()
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", router))
}
