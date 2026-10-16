package net

import (
	"crypto/rc4"

	"golang.org/x/crypto/ssh"
)

func stream(key []byte) (*rc4.Cipher, error) {
~>	return rc4.NewCipher(key)
}

func sshConfig() *ssh.ClientConfig {
	cfg := &ssh.ClientConfig{}
~>	cfg.Ciphers = append(cfg.Ciphers, "aes128-ctr", "3des-cbc")
	return cfg
}
