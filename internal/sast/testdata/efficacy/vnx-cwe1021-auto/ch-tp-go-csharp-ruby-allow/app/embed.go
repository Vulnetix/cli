package app

import "net/http"

func embeddable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
~>		w.Header().Set("X-Frame-Options", "ALLOWALL")
		next.ServeHTTP(w, r)
	})
}

func stripFrame(w http.ResponseWriter) {
~>	w.Header().Del("X-Frame-Options")
}
