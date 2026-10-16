package auth

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type AppClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func Parse(s string) (*AppClaims, error) {
	token, err := jwt.ParseWithClaims(s, &AppClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := token.Claims.(*AppClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid")
	}
	return c, nil
}
