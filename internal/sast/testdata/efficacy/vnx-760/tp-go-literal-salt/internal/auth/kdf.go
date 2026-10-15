package auth

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

~>var salt = []byte("acme-static-salt")

func Derive(password string) []byte {
	return pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
}

func DeriveInline(password string) ([]byte, error) {
~>	return scrypt.Key([]byte(password), []byte("NaCl"), 32768, 8, 1, 32)
}

func DeriveArgon(password string) []byte {
~>	return argon2.IDKey([]byte(password), []byte("fixed"), 1, 64*1024, 4, 32)
}
