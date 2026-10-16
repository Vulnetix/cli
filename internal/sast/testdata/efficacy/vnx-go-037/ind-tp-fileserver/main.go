package main

import "net/http"

func main() {
	mux := http.NewServeMux()
~>	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("public"))))
	http.ListenAndServe(":8080", mux)
}
