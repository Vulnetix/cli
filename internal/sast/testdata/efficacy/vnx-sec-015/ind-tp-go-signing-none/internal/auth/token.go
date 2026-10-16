package auth

import "github.com/golang-jwt/jwt/v5"

func Unsigned(claims jwt.MapClaims) (string, error) {
~>	t := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
~>	return t.SignedString(jwt.UnsafeAllowNoneSignatureType)
}
