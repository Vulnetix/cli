package auth

import (
	"crypto/rand"
	"encoding/hex"
)

func NewToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
