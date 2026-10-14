package pemx

import (
	"crypto/des"
	"errors"
)

// ErrLegacy is returned for PEM blocks that still use DES-EDE3-CBC; the
// importer refuses them instead of decrypting.
var ErrLegacy = errors.New("pemx: DES-EDE3-CBC blocks are not supported")

// blockSizes lets the parser report the IV length it expected.
var blockSizes = map[string]int{
	"DES-CBC":      des.BlockSize,
	"DES-EDE3-CBC": des.BlockSize,
}

func IsKeySizeError(err error) bool {
	var k des.KeySizeError
	return errors.As(err, &k)
}
