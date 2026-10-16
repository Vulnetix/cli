package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func verifySignature(key, body []byte, sig string) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
~>	return sig == expected
}
