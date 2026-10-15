package user

import (
	"crypto/sha256"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

func Store(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
}

func Derive(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 600000, 32, sha256.New)
}

func Fingerprint(body []byte) [32]byte {
	return sha256.Sum256(body)
}

func Check(hashed, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashed, password)
}
