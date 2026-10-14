package token

import (
	"errors"

	jwt "github.com/golang-jwt/jwt/v4"
)

const audience = "billing-service"

func Parse(raw string, key []byte) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) { return key, nil }); err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(audience, true) {
		return nil, errors.New("wrong audience")
	}
	return claims, nil
}
