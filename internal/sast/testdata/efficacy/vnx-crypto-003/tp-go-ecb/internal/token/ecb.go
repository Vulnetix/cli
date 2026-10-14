package token

import (
	"crypto/aes"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

// Seal encrypts each 16-byte block independently: ECB by hand.
func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	out := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += bs {
~>		block.Encrypt(out[i:i+bs], plaintext[i:i+bs])
	}
	return out, nil
}

func Open(key, ciphertext []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	for start := 0; start < len(ciphertext); start += aes.BlockSize {
		end := start + aes.BlockSize
~>		b.Decrypt(out[start:end], ciphertext[start:end])
	}
	return out, nil
}

func SealLib(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
~>	mode := ecb.NewECBEncrypter(block)
	padded, _ := padding.NewPkcs7Padding(mode.BlockSize()).Pad(plaintext)
	out := make([]byte, len(padded))
	mode.CryptBlocks(out, padded)
	return out, nil
}
