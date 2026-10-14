package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

func Verify(sig, body, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

func Token(provided, token string) bool {
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}
