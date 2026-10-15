package auth

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const saltLen = 16

func Derive(password string) ([]byte, []byte) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt, pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
}
