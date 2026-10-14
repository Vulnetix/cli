package auth

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func Check(raw string, key any) (*jwt.Claims, error) {
~>	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	out := jwt.Claims{}
	if err := tok.Claims(key, &out); err != nil {
		return nil, err
	}
	return &out, out.Validate(jwt.Expected{Issuer: "https://login.example.org", Time: time.Now()})
}
