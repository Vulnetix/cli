package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/login", adminLogin)
	srv := &http.Server{Addr: ":8080", Handler: mux}
	log.Printf("admin pages are at /admin")
	log.Fatal(srv.ListenAndServe())
	log.Fatal(http.ListenAndServe(":8081", mux))
}
