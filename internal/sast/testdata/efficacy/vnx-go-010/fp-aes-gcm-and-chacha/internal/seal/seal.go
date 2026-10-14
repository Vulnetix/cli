package seal

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type codec struct {
	nodes   []string
	modes   map[string]bool
	desc    string
	DESKeys int
}

func AEAD(key []byte, x bool) (cipher.AEAD, error) {
	if x {
		return chacha20poly1305.NewX(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
