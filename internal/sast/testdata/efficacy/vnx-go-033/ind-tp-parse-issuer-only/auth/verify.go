package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	issuer string
	keys   jwt.Keyfunc
}

func (v *Verifier) Check(raw string) (*jwt.Token, error) {
~>	tok, err := jwt.Parse(raw, v.keys, jwt.WithIssuer(v.issuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	return tok, nil
}
