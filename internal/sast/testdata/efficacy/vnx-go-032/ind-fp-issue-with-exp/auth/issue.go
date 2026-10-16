package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Issue(userID string, secret []byte) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func IssueTyped(userID string, secret []byte) (string, error) {
	c := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
}
