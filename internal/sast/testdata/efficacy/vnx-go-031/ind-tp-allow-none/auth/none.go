package auth

import "github.com/golang-jwt/jwt/v5"

func Check(raw string) (*jwt.Token, error) {
	return jwt.Parse(raw, func(t *jwt.Token) (any, error) {
~>		return jwt.UnsafeAllowNoneSignatureType, nil
	})
}
