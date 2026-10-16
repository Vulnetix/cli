package crypto

import "crypto/aes"

func subkey(key []byte) []byte {
	block, _ := aes.NewCipher(key)
	var zero, l [16]byte
	block.Encrypt(l[:], zero[:])
	return l[:]
}

func cbcManual(key, iv, pt []byte) []byte {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()
	prev := iv
	out := make([]byte, len(pt))
	for i := 0; i < len(pt); i += bs {
		x := make([]byte, bs)
		for j := range x {
			x[j] = pt[i+j] ^ prev[j]
		}
		block.Encrypt(out[i:i+bs], x)
		prev = out[i : i+bs]
	}
	return out
}
