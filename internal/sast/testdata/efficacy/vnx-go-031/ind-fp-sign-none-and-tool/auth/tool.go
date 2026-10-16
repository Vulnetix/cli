package auth

import "github.com/golang-jwt/jwt/v5"

// MakeUnsigned builds an unsigned token for a fixture.
func MakeUnsigned() (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "x"})
	return t.SignedString(jwt.UnsafeAllowNoneSignatureType)
}
