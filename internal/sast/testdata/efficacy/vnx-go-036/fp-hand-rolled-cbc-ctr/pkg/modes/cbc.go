package modes

import (
	"crypto/aes"
	"crypto/subtle"
)

func cbcEncrypt(key, iv, src []byte) []byte {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()
	dst := make([]byte, len(src))
	prev := iv
	for i := 0; i < len(src); i += bs {
		subtle.XORBytes(dst[i:i+bs], src[i:i+bs], prev)
		block.Encrypt(dst[i:i+bs], dst[i:i+bs])
		prev = dst[i : i+bs]
	}
	return dst
}

func ctr(key, iv, src []byte) []byte {
	block, _ := aes.NewCipher(key)
	ks := make([]byte, aes.BlockSize)
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += aes.BlockSize {
		block.Encrypt(ks, iv[:])
		for j := 0; j < aes.BlockSize && i+j < len(src); j++ {
			dst[i+j] = src[i+j] ^ ks[j]
		}
		inc(iv)
	}
	return dst
}
