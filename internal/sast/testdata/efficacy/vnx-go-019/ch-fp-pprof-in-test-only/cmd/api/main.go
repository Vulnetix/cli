package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
