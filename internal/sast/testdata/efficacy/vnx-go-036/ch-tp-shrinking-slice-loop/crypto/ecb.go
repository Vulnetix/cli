package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

type encrypter struct {
	b cipher.Block
}

func newEncrypter(key []byte) (*encrypter, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &encrypter{b: b}, nil
}

func (e *encrypter) CryptBlocks(dst, src []byte) {
	bs := e.b.BlockSize()
	for len(src) > 0 {
~>		e.b.Encrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
}
