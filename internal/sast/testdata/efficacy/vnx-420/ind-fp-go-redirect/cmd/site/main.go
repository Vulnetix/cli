package main

import (
	"log"
	"net/http"
)

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

func main() {
	mux := newMux()
	go http.ListenAndServe(":80", http.HandlerFunc(redirectToHTTPS))
	go http.ListenAndServe("127.0.0.1:6060", http.DefaultServeMux)
	log.Fatal(http.ListenAndServeTLS(":443", "site.crt", "site.key", mux))
}
