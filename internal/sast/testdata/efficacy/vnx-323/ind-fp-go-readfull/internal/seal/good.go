package seal

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type Box struct {
	aead  cipher.AEAD
	nonce []byte
}

func (b *Box) Seal(plaintext []byte) ([]byte, error) {
	if _, err := io.ReadFull(rand.Reader, b.nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(b.nonce, b.nonce, plaintext, nil), nil
}
