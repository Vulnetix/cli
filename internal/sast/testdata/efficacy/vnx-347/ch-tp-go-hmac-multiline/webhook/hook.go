package webhook

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"net/http"
)

func Handle(secret []byte, pub *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, secret)
		mac.Write(body)
~>		hmac.Equal(
			mac.Sum(nil),
			[]byte(r.Header.Get("X-Signature")),
		)
		digest := sha256.Sum256(body)
~>		_ = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], []byte(r.Header.Get("X-RSA-Signature")))
		process(body)
	}
}

func process(b []byte) {}
