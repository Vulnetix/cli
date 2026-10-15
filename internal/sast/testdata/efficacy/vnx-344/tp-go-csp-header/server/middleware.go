package server

import "net/http"

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
~>		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-Zm9vYmFyMTIz'")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
