package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"sync/atomic"
)

var nonceCounter uint64

func seal(aead cipher.AEAD, plaintext []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	@@sample:b[i]na[r]y[.][B]ig[E]nd[i]an[.]Pu[t]Ui[n]t6[4]@@(nonce[4:], atomic.AddUint64(&nonceCounter, 1))
	return aead.Seal(nonce, nonce, plaintext, nil)
}
