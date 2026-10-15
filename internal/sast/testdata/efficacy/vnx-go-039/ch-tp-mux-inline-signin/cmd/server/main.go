package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
~>	mux.HandleFunc("POST /signin", func(w http.ResponseWriter, r *http.Request) {
		if !checkPassword(r.FormValue("user"), r.FormValue("password")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		startSession(w, r.FormValue("user"))
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}
