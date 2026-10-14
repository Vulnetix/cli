package auth

import (
	"crypto/sha512"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

// bcrypt reads only 72 bytes, so long passphrases are pre-hashed first.
func Hash(password string) ([]byte, error) {
	pre := sha512.Sum512([]byte(password))
	enc := base64.StdEncoding.EncodeToString(pre[:])
	return bcrypt.GenerateFromPassword([]byte(enc), 12)
}

// Key is a KDF: the digest is iterated rounds times.
func Key(password, salt []byte, rounds, keyLen int) []byte {
	h := sha512.New()
	h.Write(password)
	out := h.Sum(nil)
	for i := 1; i < rounds; i++ {
		h.Reset()
		h.Write(out)
		out = h.Sum(nil)
	}
	return out[:keyLen]
}
