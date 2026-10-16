package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

// des.BlockSize is only a constant here.
const legacyBlockSize = des.BlockSize

func seal(key, nonce, pt []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, pt, nil), nil
}
