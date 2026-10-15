package main

import (
	"log"
	"net/http"

	"example.com/app/internal/server"
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("web")))
	log.Fatal(http.ListenAndServe(":8080", server.Harden(mux)))
}
