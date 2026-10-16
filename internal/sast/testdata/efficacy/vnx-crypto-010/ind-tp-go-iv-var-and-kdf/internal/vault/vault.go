package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

func DeriveKey(password string) []byte {
~>	return pbkdf2.Key([]byte(password), []byte("vault-salt-v1"), 4096, 32, sha256.New)
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
~>	iv := []byte("0000000000000000")
	mode := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(ciphertext))
	mode.CryptBlocks(out, ciphertext)
	return out, nil
}
