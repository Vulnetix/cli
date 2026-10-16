package auth

import "github.com/golang-jwt/jwt/v5"

~>var parser = jwt.NewParser(jwt.WithoutClaimsValidation())

func Parse(raw string) (*jwt.Token, error) {
	return parser.Parse(raw, keyFunc)
}
