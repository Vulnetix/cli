package session

import (
	"crypto/rand"
	"encoding/hex"
)

func NewID() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	sessionID := hex.EncodeToString(token)
	return sessionID, nil
}
