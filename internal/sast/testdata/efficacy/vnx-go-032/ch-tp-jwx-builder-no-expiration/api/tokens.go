package api

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func mint(sub string) ([]byte, error) {
~>	tok, err := jwt.NewBuilder().
		Subject(sub).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		return nil, err
	}
	return jwt.Sign(tok, jwt.WithKey(jwa.HS256, signingKey))
}
