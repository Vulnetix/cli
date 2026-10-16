package web

import (
	"log"
	"net/http"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	log.Printf("request from %s", user)
	if user == "admin" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Write([]byte("ok"))
}
