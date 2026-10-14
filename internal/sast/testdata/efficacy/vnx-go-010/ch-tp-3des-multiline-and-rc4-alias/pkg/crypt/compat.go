package crypt

import (
	"crypto/cipher"
	"crypto/des"
	arc4 "crypto/rc4"
)

func TripleDES(k1, k2, k3, iv, msg []byte) ([]byte, error) {
	key := append(append(k1, k2...), k3...)
~>	c, err := des.NewTripleDESCipher(
		key,
	)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(msg))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(out, msg)
	return out, nil
}

func Obfuscate(k, b []byte) []byte {
~>	s, _ := arc4.NewCipher(k)
	dst := make([]byte, len(b))
	s.XORKeyStream(dst, b)
	return dst
}
