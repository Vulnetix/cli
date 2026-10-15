package internal

import (
	"errors"
	"fmt"
)

var ErrInvalidToken = errors.New("invalid token")

func Load(secret *Secret, secretName string, err error) error {
	if err != nil {
		return fmt.Errorf("read secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	if secretName == "" {
		return fmt.Errorf("secret name is empty")
	}
	if len(secret.Data) == 0 {
		return fmt.Errorf("%w: secret %s has no data", ErrInvalidToken, secretName)
	}
	return nil
}

func Parse(tokenType string, passwordLen int) error {
	return fmt.Errorf("unsupported token type %q (password length %d)", tokenType, passwordLen)
}
