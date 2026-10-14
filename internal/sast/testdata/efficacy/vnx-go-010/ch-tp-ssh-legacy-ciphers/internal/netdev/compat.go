package netdev

import "golang.org/x/crypto/ssh"

var modernCiphers = []string{"aes256-gcm@openssh.com"}

~>var compatCiphers = []string{"aes128-ctr", "3des-cbc"}

func Compat(cfg *ssh.ClientConfig, legacy bool) {
	if legacy {
		cfg.Ciphers = compatCiphers
		return
	}
	cfg.Ciphers = modernCiphers
}
