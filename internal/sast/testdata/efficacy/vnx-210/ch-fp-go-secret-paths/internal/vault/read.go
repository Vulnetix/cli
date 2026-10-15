package vault

import (
	"errors"
	"fmt"
)

var ErrNoToken = errors.New("vault token not set")

func Read(c *Client, secretPath string, tokenTTL int) (string, error) {
	if c.Token == "" {
		return "", ErrNoToken
	}
	v, err := c.Logical().Read(secretPath)
	if err != nil {
		return "", fmt.Errorf("reading secret at %s: %w", secretPath, err)
	}
	if tokenTTL <= 0 {
		return "", fmt.Errorf("token ttl %d is not positive", tokenTTL)
	}
	return v, nil
}
