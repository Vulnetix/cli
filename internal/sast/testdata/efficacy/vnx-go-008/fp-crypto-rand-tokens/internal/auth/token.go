package auth

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	mrand "math/rand"
)

func NewSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func GenerateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

// pickBackend spreads load; it is not a secret.
func pickBackend(backends []string) string {
	return backends[mrand.Intn(len(backends))]
}
