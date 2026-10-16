package cmac

import "crypto/cipher"

// subkeys derives K1 and K2 per RFC 4493 from one encryption of the zero block.
func subkeys(b cipher.Block) (k1, k2 []byte) {
	l := make([]byte, b.BlockSize())
	b.Encrypt(l, l)
	k1 = shiftLeft(l)
	k2 = shiftLeft(k1)
	return k1, k2
}
