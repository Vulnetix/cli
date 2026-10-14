package middleware

import (
	"context"
	"net/http"

	jwt "github.com/golang-jwt/jwt/v4"
)

type ctxKey struct{}

func keyFunc(t *jwt.Token) (interface{}, error) { return hmacSecret, nil }

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")[7:]
~>		token, _ := jwt.Parse(bearer, keyFunc)
		claims := token.Claims.(jwt.MapClaims)
		ctx := context.WithValue(r.Context(), ctxKey{}, claims["sub"])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type session struct {
	Org string `json:"org"`
	jwt.RegisteredClaims
}

func orgOf(r *http.Request) string {
	c, _ := r.Cookie("session")
~>	tok, _ := jwt.ParseWithClaims(c.Value, &session{},
		keyFunc)
	return tok.Claims.(*session).Org
}
