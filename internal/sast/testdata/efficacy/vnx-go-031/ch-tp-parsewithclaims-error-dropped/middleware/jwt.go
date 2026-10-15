package middleware

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c Claims
~>		_, _ = jwt.ParseWithClaims(r.Header.Get("X-Token"), &c, keyFunc)
		if c.UserID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), c.UserID)))
	})
}
