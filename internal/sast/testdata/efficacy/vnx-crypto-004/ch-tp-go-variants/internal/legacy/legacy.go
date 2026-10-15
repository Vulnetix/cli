package legacy

import (
	"crypto/des"
	"crypto/rc4"

	"golang.org/x/crypto/blowfish"
)

func Ciphers(k []byte) {
~>	tdes, _ := des.NewTripleDESCipher(k)
~>	stream, _ := rc4.NewCipher(k)
~>	bf, _ := blowfish.NewCipher(k)
	_, _, _ = tdes, stream, bf
}
