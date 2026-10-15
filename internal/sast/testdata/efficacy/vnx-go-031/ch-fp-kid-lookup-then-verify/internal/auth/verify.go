package auth

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func Verify(r *http.Request, raw string) (*jwt.Token, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	kid, _ := unverified.Header["kid"].(string)
	key, ok := keys[kid]
	if !ok {
		return nil, errors.New("unknown key")
	}
	return jwt.Parse(raw, func(t *jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"RS256"}))
}
