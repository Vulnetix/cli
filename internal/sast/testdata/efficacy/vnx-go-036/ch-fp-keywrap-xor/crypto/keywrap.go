package crypto

import (
	"crypto/aes"
	"encoding/binary"
)

// Wrap implements RFC 3394 AES key wrap.
func Wrap(kek, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	r := make([][]byte, n)
	for i := range r {
		r[i] = append([]byte{}, key[i*8:i*8+8]...)
	}
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	b := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b, a)
			copy(b[8:], r[i])
			block.Encrypt(b, b)
			t := uint64(n*j + i + 1)
			v := @@sample:b[i]na[r]y[.][B]ig[E]nd[i]an[.]Ui[n]t6[4]@@(b[:8]) ^ t
			@@sample:b[i]na[r]y[.][B]ig[E]nd[i]an[.]Pu[t]Ui[n]t6[4]@@(a, v)
			copy(r[i], b[8:])
		}
	}
	out := append([]byte{}, a...)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out, nil
}
