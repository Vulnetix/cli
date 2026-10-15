package auth

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

type serviceClaims struct {
	Aud   string `json:"aud"`
	Scope string `json:"scope"`
	jwt.StandardClaims
}

func (s *Service) check(raw string) (*serviceClaims, error) {
	c := &serviceClaims{}
	_, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if c.Aud != s.clientID {
		return nil, errors.New("token not issued for this service")
	}
	return c, nil
}
