package tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// subkey derives a per-message key by encrypting one random block.
func subkey(master []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, nil, err
	}
	seed := make([]byte, aes.BlockSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	k := make([]byte, aes.BlockSize)
	block.Encrypt(k, seed)
	return k, seed, nil
}

func seal(key, nonce, msg []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, msg, nil), nil
}
