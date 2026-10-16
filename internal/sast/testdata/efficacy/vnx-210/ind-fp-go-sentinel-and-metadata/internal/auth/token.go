package auth

import (
	"errors"
	"fmt"
)

var ErrInvalidToken = errors.New("invalid token")

type Secret struct {
	Name  string
	Value []byte
}

func check(token string, secret Secret) error {
	if len(token) == 0 {
		return ErrInvalidToken
	}
	if len(secret.Value) < 32 {
		return fmt.Errorf("secret %s too short: %d bytes", secret.Name, len(secret.Value))
	}
	return nil
}
