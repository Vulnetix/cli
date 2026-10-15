package auth

import "github.com/golang-jwt/jwt/v5"

func Verify(raw string, key []byte) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	return claims, err
}
