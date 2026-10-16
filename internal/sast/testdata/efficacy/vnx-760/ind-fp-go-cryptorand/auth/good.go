package auth

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

func Hash(password string) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32), salt, nil
}
