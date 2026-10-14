package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

// blockCiphers maps a configured algorithm name to its constructor; "3des"
// stays selectable by configuration.
var blockCiphers = map[string]func([]byte) (cipher.Block, error){
	"aes":  aes.NewCipher,
~>	"3des": des.NewTripleDESCipher,
}
