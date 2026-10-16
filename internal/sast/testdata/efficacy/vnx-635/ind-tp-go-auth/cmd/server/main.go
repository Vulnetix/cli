package main

import "net/http"

func main() {
~>	// TODO: add authentication before exposing this handler
	http.HandleFunc("/admin", adminHandler)
	http.ListenAndServe(":8080", nil)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {}
