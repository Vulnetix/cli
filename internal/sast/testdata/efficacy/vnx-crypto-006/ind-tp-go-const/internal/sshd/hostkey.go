package sshd

import (
	"crypto/rand"
	"crypto/rsa"
)

const hostKeyBits = 1024

func newHostKey() (*rsa.PrivateKey, error) {
~>	return rsa.GenerateKey(rand.Reader, hostKeyBits)
}
