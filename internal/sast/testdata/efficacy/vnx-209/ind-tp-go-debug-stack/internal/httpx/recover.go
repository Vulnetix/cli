package httpx

import (
	"log"
	"net/http"
	"runtime/debug"
)

// Recover turns a panic in a handler into a 500 response.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic: %v", rec)
				w.WriteHeader(http.StatusInternalServerError)
~>				w.Write(debug.Stack())
			}
		}()
		next.ServeHTTP(w, r)
	})
}
