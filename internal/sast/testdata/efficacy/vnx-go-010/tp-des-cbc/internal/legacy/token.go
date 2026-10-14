package legacy

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"io"
)

// Seal encrypts session tokens with single DES in CBC mode.
func Seal(key, plaintext []byte) ([]byte, error) {
~>	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, des.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return append(iv, out...), nil
}
