package api

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func mint(sub string) ([]byte, error) {
	tok, err := jwt.NewBuilder().
		Subject(sub).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		return nil, err
	}
	return jwt.Sign(tok, jwt.WithKey(jwa.HS256, signingKey))
}

func verify(raw []byte) (jwt.Token, error) {
	return jwt.Parse(raw, jwt.WithKey(jwa.HS256, signingKey), jwt.WithValidate(true))
}
