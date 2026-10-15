package main

import (
	"log"
	"net/http"
)

func upgrade(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func main() {
	mux := buildMux()
	srv := &http.Server{Addr: ":443", Handler: mux}
	go func() {
		log.Fatal(srv.ListenAndServeTLS("tls.crt", "tls.key"))
	}()

	log.Println("starting")
	log.Println("listening for plain HTTP")
	log.Println("all requests are upgraded")
	log.Println("see upgrade()")
	log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(upgrade)))
}
