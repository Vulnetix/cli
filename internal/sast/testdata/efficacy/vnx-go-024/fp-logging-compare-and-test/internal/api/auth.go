package api

import (
	"crypto/subtle"
	"log"
	"net/http"
)

// Reading, logging and comparing a parameter is not passing it to a sink.
func Auth(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request from %s", r.Header.Get("User-Agent"))
		got := r.Header.Get("X-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		// exec.Command("sh", "-c", r.FormValue("cmd"))
		next.ServeHTTP(w, r)
	})
}
