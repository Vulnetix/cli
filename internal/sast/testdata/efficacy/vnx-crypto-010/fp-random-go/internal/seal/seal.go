package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func Seal(gcm cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Open(gcm cipher.AEAD, data []byte) ([]byte, error) {
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("short")
	}
	nonce, ct := data[:ns], data[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

func CBC(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize+len(plaintext))
	iv := out[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[aes.BlockSize:], plaintext)
	return out, nil
}

func CTR(key []byte, iv []byte, data []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(out, data)
	return out
}

func Derive(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 600000, 32, sha256.New)
}
