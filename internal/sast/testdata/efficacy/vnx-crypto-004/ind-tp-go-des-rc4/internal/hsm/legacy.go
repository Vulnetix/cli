package hsm

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
)

func tripleDES(key []byte) (cipher.Block, error) {
~>	return des.NewTripleDESCipher(key)
}

func keystream(key, data []byte) ([]byte, error) {
~>	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}
