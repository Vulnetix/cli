package session

import (
	"crypto/rsa"

	jwt "github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func Verify(raw string, pub *rsa.PublicKey) (*Claims, error) {
	claims := &Claims{}
~>	_, err := jwt.ParseWithClaims(
		raw,
		claims,
		func(t *jwt.Token) (interface{}, error) {
			return pub, nil
		},
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
