package token

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	UserID string `json:"uid"`
~>	Password string `json:"password"`
	jwt.RegisteredClaims
}
