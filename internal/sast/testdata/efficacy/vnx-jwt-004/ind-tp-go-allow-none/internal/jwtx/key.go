package jwtx

import "github.com/golang-jwt/jwt/v5"

func Keyfunc(t *jwt.Token) (interface{}, error) {
~>	return jwt.UnsafeAllowNoneSignatureType, nil
}
