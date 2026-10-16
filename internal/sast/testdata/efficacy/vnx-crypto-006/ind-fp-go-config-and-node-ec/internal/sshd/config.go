package sshd

import (
	"crypto/rand"
	"crypto/rsa"
)

type Config struct {
	KeyBits int
}

func keyFromConfig(cfg Config) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, cfg.KeyBits)
}

func defaultKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// The old code used rsa.GenerateKey(rand.Reader, 1024) here.
var bufSize = 1024
