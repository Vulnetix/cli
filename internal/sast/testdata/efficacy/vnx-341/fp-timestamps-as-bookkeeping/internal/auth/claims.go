package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Claims(sub string) jwt.MapClaims {
	start := time.Now()
	claims := jwt.MapClaims{"sub": sub, "exp": time.Now().Add(time.Hour).Unix()}
	_ = start
	return claims
}
