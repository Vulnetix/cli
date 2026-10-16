package auth

import "golang.org/x/crypto/scrypt"

func Derive(password string) ([]byte, error) {
~>	return scrypt.Key([]byte(password), []byte("NaCl"), 32768, 8, 1, 32)
}
