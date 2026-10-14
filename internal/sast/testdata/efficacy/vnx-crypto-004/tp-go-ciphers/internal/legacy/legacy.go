package legacy

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"

	bf "golang.org/x/crypto/blowfish"
)

func Encrypt(key, iv, data []byte) ([]byte, error) {
~>	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

func Single(key []byte) (cipher.Block, error) {
~>	return des.NewCipher(key)
}

func Stream(key, data []byte) ([]byte, error) {
~>	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

func Fish(key []byte) (*bf.Cipher, error) {
~>	return bf.NewCipher(key)
}
