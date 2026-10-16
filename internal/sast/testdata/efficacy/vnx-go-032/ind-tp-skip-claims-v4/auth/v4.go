package auth

import "github.com/golang-jwt/jwt/v4"

func New() *jwt.Parser {
~>	return &jwt.Parser{SkipClaimsValidation: true}
}
