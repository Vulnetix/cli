package auth

import (
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

func Verify(raw string, jwks keyfunc.Keyfunc) (*jwt.Token, error) {
~>	return jwt.Parse(raw, jwks.Keyfunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://idp.example.com/"))
}
