package compat

import "crypto/des"

// DecryptLegacy reads records written by the old billing system.
func DecryptLegacy(key, data []byte) ([]byte, error) {
	c, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	bs := c.BlockSize()
	out := make([]byte, len(data))
	for start := 0; start+bs <= len(data); start += bs {
~>		c.Decrypt(out[start:start+bs], data[start:start+bs])
	}
	return out, nil
}
