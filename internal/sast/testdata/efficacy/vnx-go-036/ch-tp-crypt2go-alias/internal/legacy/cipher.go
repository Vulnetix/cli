package legacy

import (
	"crypto/aes"

	modes "github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

func Seal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
~>	mode := modes.NewECBEncrypter(block)
	padded, err := @@sample:p[a]dd[i]ng[.]Ne[w]Pk[c]s7[P]ad[d]in[g]@@(aes.BlockSize).Pad(plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(padded))
	mode.CryptBlocks(out, padded)
	return out, nil
}
