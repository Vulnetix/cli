package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
)

func validSignature(key, body, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

type entry struct{ Token string }

// release drops a cache entry only if it is still the one this process issued.
func release(cache map[string]*entry, key, tok string) {
	if e := cache[key]; e != nil && e.Token == tok {
		delete(cache, key)
	}
}

type layer struct{ Digest string }

func sameLayer(from, to layer) bool {
	return from.Digest == to.Digest
}
