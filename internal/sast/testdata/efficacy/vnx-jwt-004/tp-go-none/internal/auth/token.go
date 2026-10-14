package auth

import "github.com/golang-jwt/jwt/v5"

func Issue(user string) (string, error) {
~>	t := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": user})
~>	return t.SignedString(jwt.UnsafeAllowNoneSignatureType)
}

func Parse(raw string) (*jwt.Token, error) {
	return jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
~>		return jwt.UnsafeAllowNoneSignatureType, nil
	})
}
