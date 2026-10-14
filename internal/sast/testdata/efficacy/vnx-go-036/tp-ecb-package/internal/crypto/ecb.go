package crypto

import (
	"crypto/aes"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

func Encrypt(key, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
~>	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, _ = padder.Pad(pt)
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct, nil
}

func Decrypt(key, ct []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(ct))
~>	ecb.NewECBDecrypter(block).CryptBlocks(out, ct)
	return out
}
