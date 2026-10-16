package webhook

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
)

var secret = []byte("from-config")

func Handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	got, _ := hex.DecodeString(r.Header.Get("X-Hub-Signature-256"))
~>	hmac.Equal(mac.Sum(nil), got)
	process(body)
}

func VerifyRelease(pub ed25519.PublicKey, blob, sig []byte) []byte {
~>	_ = ed25519.Verify(pub, blob, sig)
	return blob
}

func process(b []byte) {}
