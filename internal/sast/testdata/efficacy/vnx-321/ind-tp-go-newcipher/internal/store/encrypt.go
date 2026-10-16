package store

import (
	"crypto/aes"
	"crypto/cipher"
)

func newAEAD() (cipher.AEAD, error) {
~>	block, err := aes.NewCipher([]byte("p4Kd9Lw2Xq7Rz1Mn8Bv3Tc6Yh0Ja5Ef2"))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
