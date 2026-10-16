package api

import (
	"crypto/rand"
	"encoding/base64"
	mrand "math/rand"
	"time"
)

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pollInterval() time.Duration {
	return time.Second + time.Duration(mrand.Intn(500))*time.Millisecond
}
