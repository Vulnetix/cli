package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Issue(userID string, secret []byte) (string, error) {
~>	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
	}).SignedString(secret)
}
