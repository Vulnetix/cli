package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
)

func EncryptWithKeyIV(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
~>	cipher.NewCBCEncrypter(block, key[:aes.BlockSize]).CryptBlocks(out, plain)
	return out, nil
}

func EncryptRandomIV(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
~>	rand.Read(iv)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return append(iv, out...), nil
}
