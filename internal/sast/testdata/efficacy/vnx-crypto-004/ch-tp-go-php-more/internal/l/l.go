package l

import (
	"crypto/des"

	"golang.org/x/crypto/cast5"
)

func Run(k []byte) {
~>	a, _ := des.NewCipher(k)
~>	b, _ := cast5.NewCipher(k)
	_, _ = a, b
}
