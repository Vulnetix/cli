package auth

import "github.com/lestrrat-go/jwx/v2/jwt"

func Subject(raw []byte) (string, error) {
~>	tok, err := jwt.Parse(raw, jwt.WithVerify(false), jwt.WithValidate(true))
	if err != nil {
		return "", err
	}
	return tok.Subject(), nil
}

func Claims(raw []byte) (jwt.Token, error) {
~>	return jwt.ParseInsecure(raw)
}
