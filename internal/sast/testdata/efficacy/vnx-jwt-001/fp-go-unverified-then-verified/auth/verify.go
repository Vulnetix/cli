package auth

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// ParseUnverified is only used to read the kid; the token is verified below.
func Verify(raw string, keys map[string][]byte) (*jwt.Token, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	kid, _ := unverified.Header["kid"].(string)
	key, ok := keys[kid]
	if !ok {
		return nil, errors.New("unknown key")
	}
	return jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) { return key, nil },
		jwt.WithValidMethods([]string{"HS256"}))
}
