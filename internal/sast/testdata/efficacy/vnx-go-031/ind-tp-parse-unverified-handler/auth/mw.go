package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims := jwt.MapClaims{}
~>		_, _, err := jwt.NewParser().ParseUnverified(bearer, claims)
		if err != nil {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		r.Header.Set("X-User", claims["sub"].(string))
		next.ServeHTTP(w, r)
	})
}
