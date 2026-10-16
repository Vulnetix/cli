package seal

import "crypto/cipher"

type Sealer struct {
	aead  cipher.AEAD
	nonce []byte
}

func (s *Sealer) Seal(plaintext []byte) []byte {
~>	return s.aead.Seal(nil, s.nonce, plaintext, nil)
}
