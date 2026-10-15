package main

import (
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	go func() {
		log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
		})))
	}()
	go log.Fatal(http.ListenAndServe("127.0.0.1:6060", nil))
	ln, _ := net.Listen("unix", "/run/app.sock")
	os.Chmod("/run/app.sock", 0o600)
	os.Chmod("/run/app.sock", 0660)
	log.Fatal(http.ServeTLS(ln, mux, "c.pem", "k.pem"))
}
