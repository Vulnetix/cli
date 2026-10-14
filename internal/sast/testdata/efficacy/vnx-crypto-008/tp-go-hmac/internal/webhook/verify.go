package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

func Verify(r *http.Request, body, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	sig := r.Header.Get("X-Signature")
~>	return sig == expected
}

func VerifyInline(r *http.Request, body, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
~>	return hex.EncodeToString(mac.Sum(nil)) == r.Header.Get("X-Signature")
}
