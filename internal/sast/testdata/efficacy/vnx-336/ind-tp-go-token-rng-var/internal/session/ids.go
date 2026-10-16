package session

import (
	"encoding/hex"
	"math/rand"
)

~>var tokenRng = rand.New(rand.NewSource(424242))

// NewSessionToken returns a hex token for the session cookie.
func NewSessionToken() string {
	b := make([]byte, 16)
	tokenRng.Read(b)
	return hex.EncodeToString(b)
}
