package box

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type Box struct {
	aead  cipher.AEAD
	nonce []byte
}

func (b *Box) Seal(msg []byte) []byte {
	if _, err := io.ReadFull(rand.Reader, b.nonce); err != nil {
		panic(err)
	}
	return b.aead.Seal(nil, b.nonce, msg, nil)
}
