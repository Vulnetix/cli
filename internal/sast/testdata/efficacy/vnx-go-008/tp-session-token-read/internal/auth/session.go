package auth

import (
	"encoding/hex"
	"math/rand"
)

// NewSessionID returns the identifier stored in the session cookie.
func NewSessionID() string {
	b := make([]byte, 16)
~>	rand.Read(b)
	return hex.EncodeToString(b)
}

func issueCSRF() string {
~>	return hex.EncodeToString([]byte{byte(rand.Intn(256)), byte(rand.Intn(256))})
}
