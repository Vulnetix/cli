package auth

import "github.com/golang-jwt/jwt/v5"

~>var parser = jwt.NewParser(
	jwt.WithValidMethods([]string{"HS256"}),
)

func Decode(raw string, secret []byte) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) { return secret, nil })
	return claims, err
}
