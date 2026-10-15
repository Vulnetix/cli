package session

import (
	"errors"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	key []byte
}

func (m *Manager) Verify(raw string) (*jwtlib.RegisteredClaims, error) {
	claims := &jwtlib.RegisteredClaims{}
~>	tok, err := jwtlib.ParseWithClaims(raw, claims, func(t *jwtlib.Token) (any, error) {
		return m.key, nil
	}, jwtlib.WithIssuer("https://idp.example.com"), jwtlib.WithValidMethods([]string{"HS256"}))
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid session")
	}
	return claims, nil
}
