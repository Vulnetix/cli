package box

import "crypto/cipher"

type Sealer struct {
	block cipher.Block
	iv    []byte
}

func NewSealer(b cipher.Block, iv []byte) *Sealer {
	return &Sealer{block: b, iv: iv}
}

func (s *Sealer) Encrypt(dst, src []byte) {
~>	stream := cipher.NewCTR(s.block, s.iv)
	stream.XORKeyStream(dst, src)
}
