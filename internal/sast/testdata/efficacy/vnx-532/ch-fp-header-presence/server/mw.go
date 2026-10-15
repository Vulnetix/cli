package server

import (
	"log"
	"net/http"
)

func audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("path=%s authenticated=%t", r.URL.Path, r.Header.Get("Authorization") != "")
		log.Printf("headers=%d", len(r.Header))
		next.ServeHTTP(w, r)
	})
}
