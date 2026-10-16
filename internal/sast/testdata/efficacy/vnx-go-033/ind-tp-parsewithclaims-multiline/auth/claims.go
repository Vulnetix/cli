package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type AppClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func Middleware(keyFunc jwt.Keyfunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims := &AppClaims{}
~>		tok, err := jwt.ParseWithClaims(
			raw,
			claims,
			keyFunc,
			jwt.WithValidMethods([]string{"RS256"}),
		)
		if err != nil || !tok.Valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
