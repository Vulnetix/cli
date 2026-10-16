package authn

import "github.com/golang-jwt/jwt/v5"

// Note: we never call ParseUnverified here; the signature is always checked.
func Verify(raw string, key []byte) (*jwt.Token, error) {
	return jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
}
