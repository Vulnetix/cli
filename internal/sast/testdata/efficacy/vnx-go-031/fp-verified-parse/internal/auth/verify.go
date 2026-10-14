package auth

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func Verify(r *http.Request) (*Claims, error) {
	raw := r.Header.Get("Authorization")
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected method %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func Parse(r *http.Request) (jwt.MapClaims, error) {
	token, err := jwt.Parse(r.Header.Get("Authorization"), keyFunc)
	if err != nil {
		return nil, err
	}
	return token.Claims.(jwt.MapClaims), nil
}
