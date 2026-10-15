package auth

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

func DeriveKey(password string) []byte {
~>	salt := []byte("pepper-and-salt")
	return pbkdf2.Key([]byte(password), salt, 210000, 32, sha256.New)
}

func HashPassword(password string) []byte {
~>	return argon2.IDKey([]byte(password), []byte("somesalt"), 1, 64*1024, 4, 32)
}
