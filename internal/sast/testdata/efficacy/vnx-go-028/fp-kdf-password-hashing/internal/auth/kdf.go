package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func Argon(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func PBKDF2(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 600_000, 32, sha256.New)
}

func Legacy(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 1_300_000, 20, sha1.New)
}

func Scrypt(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	return scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
}

func MAC(passwordKey, msg []byte) []byte {
	m := hmac.New(sha256.New, passwordKey)
	m.Write(msg)
	return m.Sum(nil)
}
