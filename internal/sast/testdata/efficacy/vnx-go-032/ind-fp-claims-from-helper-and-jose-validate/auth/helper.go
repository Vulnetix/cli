package auth

import (
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	gj "github.com/golang-jwt/jwt/v5"
)

func Sign(c gj.Claims, secret []byte) (string, error) {
	return gj.NewWithClaims(gj.SigningMethodHS256, c).SignedString(secret)
}

func Verify(tok *jwt.JSONWebToken, key any) error {
	var c jwt.Claims
	if err := tok.Claims(key, &c); err != nil {
		return err
	}
	return c.ValidateWithLeeway(jwt.Expected{Issuer: "idp"}, time.Minute)
}
