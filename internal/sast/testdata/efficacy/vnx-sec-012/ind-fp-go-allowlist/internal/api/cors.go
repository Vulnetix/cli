package api

import "net/http"

var allowedOrigins = map[string]bool{
	"https://app.shop.example":   true,
	"https://admin.shop.example": true,
}

func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		next.ServeHTTP(w, r)
	})
}
