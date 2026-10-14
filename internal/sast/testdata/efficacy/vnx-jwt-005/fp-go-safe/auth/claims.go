package auth

import "github.com/golang-jwt/jwt/v5"

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}
