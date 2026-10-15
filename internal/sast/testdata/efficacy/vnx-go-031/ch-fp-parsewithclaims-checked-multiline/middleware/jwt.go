package middleware

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c Claims
		tok, err := jwt.ParseWithClaims(
			r.Header.Get("X-Token"),
			&c,
			keyFunc,
			jwt.WithValidMethods([]string{"HS256"}),
		)
		if err != nil || !tok.Valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
