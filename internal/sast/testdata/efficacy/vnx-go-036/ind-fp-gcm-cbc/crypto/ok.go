package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func SealGCM(key, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, pt, nil), nil
}

func SealCBC(key, iv, pt []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, pt)
	return out
}
