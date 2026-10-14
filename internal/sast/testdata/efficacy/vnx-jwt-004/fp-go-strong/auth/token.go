package auth

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// Never return jwt.UnsafeAllowNoneSignatureType from a key func.
func Parse(raw string, key []byte) (*jwt.Token, error) {
	return jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if t.Method == jwt.SigningMethodNone {
			return nil, errors.New("unsigned token")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
}
