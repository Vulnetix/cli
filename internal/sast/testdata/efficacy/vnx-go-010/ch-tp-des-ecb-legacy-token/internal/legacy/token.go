package legacy

import (
	"crypto/des"
	"errors"
)

// DecryptToken reads tokens issued by the old Java service.
func DecryptToken(key, data []byte) ([]byte, error) {
~>	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%des.BlockSize != 0 {
		return nil, errors.New("bad length")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += des.BlockSize {
		block.Decrypt(out[i:i+des.BlockSize], data[i:i+des.BlockSize])
	}
	return out, nil
}
