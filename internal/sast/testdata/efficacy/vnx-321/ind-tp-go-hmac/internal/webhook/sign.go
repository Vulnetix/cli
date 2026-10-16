package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
)

func Sign(body []byte) []byte {
~>	mac := hmac.New(sha256.New, []byte("wH7tK2pN9qL4mX8zR3vB6cY1"))
	mac.Write(body)
	return mac.Sum(nil)
}
