package secrets

import (
	"errors"
	"fmt"
)

var ErrTokenExpired = errors.New("token expired")

func Fetch(secretID string, tokenErr error) error {
	if tokenErr != nil {
		return fmt.Errorf("parsing token: %w", tokenErr)
	}
	if secretID == "" {
		return fmt.Errorf("decrypt secret %q: not found", secretID)
	}
	return ErrTokenExpired
}

func Validate(passwordLen int, tokenTTL int) error {
	if passwordLen < 12 {
		return fmt.Errorf("password too short: %d characters", passwordLen)
	}
	if tokenTTL <= 0 {
		return fmt.Errorf("token ttl must be positive, got %d", tokenTTL)
	}
	return nil
}
