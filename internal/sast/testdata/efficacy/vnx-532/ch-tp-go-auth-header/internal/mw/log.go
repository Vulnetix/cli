package mw

import (
	"log"
	"net/http"
)

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
~>		log.Printf("method=%s auth=%s", r.Method, r.Header.Get("Authorization"))
		next.ServeHTTP(w, r)
	})
}
