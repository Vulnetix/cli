package auth

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

func Validate(raw string, kf jwt.Keyfunc) error {
	claims := &jwt.RegisteredClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, kf)
	if err != nil || !tok.Valid {
		return err
	}
	if !claims.VerifyAudience("inventory-service", true) {
		return errors.New("wrong audience")
	}
	return nil
}
