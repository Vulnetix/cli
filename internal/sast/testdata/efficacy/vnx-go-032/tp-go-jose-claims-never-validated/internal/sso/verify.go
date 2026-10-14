package sso

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type idToken struct {
	Email string `json:"email"`
	jwt.Claims
}

func VerifyIDToken(raw string) (*idToken, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	out := &idToken{}
~>	if err := tok.Claims(providerKey, out); err != nil {
		return nil, err
	}
	return out, nil
}

func VerifyAccess(raw string) (map[string]any, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	var std jwt.Claims
	extra := map[string]any{}
~>	err = tok.Claims(&signingKey.PublicKey, &std, &extra)
	if err != nil {
		return nil, err
	}
	return extra, nil
}
