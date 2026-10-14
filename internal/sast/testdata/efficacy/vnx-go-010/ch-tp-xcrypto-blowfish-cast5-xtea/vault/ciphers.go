package vault

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/xtea"
)

func blockFor(alg string, key, salt []byte) (cipher.Block, error) {
	switch alg {
	case "blowfish":
~>		return blowfish.NewCipher(append(key, salt...))
	case "cast5":
~>		return cast5.NewCipher(key)
	case "xtea":
~>		return xtea.NewCipher(key)
	default:
		return aes.NewCipher(key)
	}
}

~>var legacyCtors = map[string]func([]byte) (cipher.Block, error){"xtea": xtea.NewCipher, "aes": aes.NewCipher}
