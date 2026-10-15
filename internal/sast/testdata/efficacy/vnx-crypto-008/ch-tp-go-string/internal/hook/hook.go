package hook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

func Verify(r *http.Request, body, key []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	expectedMAC := hex.EncodeToString(m.Sum(nil))
~>	return expectedMAC == r.Header.Get("X-Signature")
}
