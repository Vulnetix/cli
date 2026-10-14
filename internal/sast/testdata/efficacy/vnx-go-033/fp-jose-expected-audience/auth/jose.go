package auth

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func Check(raw string, key any) error {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return err
	}
	out := jwt.Claims{}
	if err := tok.Claims(key, &out); err != nil {
		return err
	}
	return out.Validate(jwt.Expected{Issuer: "https://login.example.org", AnyAudience: jwt.Audience{"orders"}})
}
