package legacy

import (
	"crypto/cipher"
	"crypto/des"
)

func Encrypt3DES(key, p []byte) []byte {
	c, _ := des.NewTripleDESCipher(key)
	out := make([]byte, len(p))
	for off := 0; off < len(p); off += c.BlockSize() {
~>		c.Encrypt(out[off:], p[off:])
	}
	return out
}

func encryptBlocks(b cipher.Block, dst, src []byte) {
	n := b.BlockSize()
	for i := 0; i+n <= len(src); i += n {
~>		b.Encrypt(dst[i:], src[i:])
	}
}
