package auth

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

func keyFunc(key []byte) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if t.Method == jwt.SigningMethodNone {
			return nil, errors.New("none is not allowed")
		}
		return key, nil
	}
}
