package sso

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func VerifyIDToken(raw string) (*jwt.Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	var c jwt.Claims
	if err := tok.Claims(providerKey, &c); err != nil {
		return nil, err
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: "https://idp.example", Time: time.Now()}, time.Minute); err != nil {
		return nil, err
	}
	return &c, nil
}
