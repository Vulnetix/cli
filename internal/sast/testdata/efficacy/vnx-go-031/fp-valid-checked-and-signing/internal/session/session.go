package session

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

func Read(r *http.Request) (jwt.MapClaims, error) {
	c, err := r.Cookie("session")
	if err != nil {
		return nil, err
	}
	token, _ := jwt.Parse(c.Value, keyFunc)
	if token == nil || !token.Valid {
		return nil, errors.New("invalid session")
	}
	return token.Claims.(jwt.MapClaims), nil
}

// An unsigned token for a local dev fixture server; nothing parses it here.
func DevToken() string {
	s, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "dev"}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	return s
}

func Check(r *http.Request) bool {
	_, err := jwt.Parse(r.Header.Get("Authorization"), keyFunc)
	return err == nil
}
