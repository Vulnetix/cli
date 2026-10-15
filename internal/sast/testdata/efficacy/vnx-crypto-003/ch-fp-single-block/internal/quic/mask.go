package quic

import "crypto/cipher"

// headerMask computes the QUIC header-protection mask from one sample block.
func headerMask(block cipher.Block, sample []byte) []byte {
	mask := make([]byte, block.BlockSize())
	block.Encrypt(mask, sample)
	return mask
}
