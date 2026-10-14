package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// subkey encrypts one zero block, as CMAC (RFC 4493) specifies.
func subkey(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	l := make([]byte, aes.BlockSize)
	block.Encrypt(l, l)
	return l, nil
}

func ctrStream(block cipher.Block, iv, dst, src []byte) {
	stream := cipher.NewCTR(block, iv)
	for i := 0; i < len(src); i += 4096 {
		stream.XORKeyStream(dst[i:], src[i:])
	}
}
