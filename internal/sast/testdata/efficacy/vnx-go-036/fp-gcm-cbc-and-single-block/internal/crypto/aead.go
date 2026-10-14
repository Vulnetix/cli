package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

func Seal(key, nonce, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, pt, nil), nil
}

func CBC(key, iv, pt []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, pt)
	return out
}

// subkey derives a CMAC subkey from a single block: one block, not a mode.
func subkey(key []byte) []byte {
	block, _ := aes.NewCipher(key)
	l := make([]byte, aes.BlockSize)
	block.Encrypt(l, l)
	return l
}

func keys(blocks [][]byte, key []byte) {
	block, _ := aes.NewCipher(key)
	for _, b := range blocks {
		gcm, _ := cipher.NewGCM(block)
		_ = gcm.Seal(nil, b[:12], b, nil)
	}
}
