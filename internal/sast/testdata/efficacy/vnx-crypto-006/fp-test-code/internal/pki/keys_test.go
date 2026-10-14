package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSign(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	_ = k
}
