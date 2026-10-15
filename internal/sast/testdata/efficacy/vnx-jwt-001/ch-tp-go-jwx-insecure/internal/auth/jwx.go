package auth

import (
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func Subject(raw []byte) (string, error) {
~>	tok, err := jwt.ParseInsecure(raw)
	if err != nil {
		return "", err
	}
	return tok.Subject(), nil
}

func Lenient(raw []byte) (jwt.Token, error) {
~>	return jwt.Parse(raw, jwt.WithVerify(false))
}
