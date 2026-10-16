package crypto

import "crypto/des"

func Seal(k, p []byte) []byte {
	c, _ := des.NewTripleDESCipher(k)
	out := make([]byte, len(p))
	for off := 0; off < len(p); off += c.BlockSize() {
~>		c.Encrypt(out[off:], p[off:])
	}
	return out
}
