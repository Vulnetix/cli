package api

import (
	"fmt"
	mrand "math/rand"
	"net/http"
)

func signRequest(req *http.Request, key string) {
~>	nonce := fmt.Sprintf("%016x", mrand.Uint64())
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", hmacSign(key, req.URL.Path+nonce))
}
