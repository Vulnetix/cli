package auth

import "github.com/golang-jwt/jwt/v5"

type SessionClaims struct {
	UserID            string `json:"uid"`
	PasswordChangedAt int64  `json:"pca"`
	jwt.RegisteredClaims
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
