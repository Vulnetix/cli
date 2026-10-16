package auth

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func legacyHash(password string) string {
~>	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func fastBcrypt(password string) ([]byte, error) {
~>	return bcrypt.GenerateFromPassword([]byte(password), 8)
}
