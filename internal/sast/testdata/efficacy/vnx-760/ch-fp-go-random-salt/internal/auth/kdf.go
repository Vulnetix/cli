package auth

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const saltLen = 16

func Derive(password string) ([]byte, []byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	return salt, pbkdf2.Key([]byte(password), salt, 210000, 32, sha256.New), nil
}

func Verify(password string, salt, want []byte) bool {
	got, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	return err == nil && string(got) == string(want)
}
