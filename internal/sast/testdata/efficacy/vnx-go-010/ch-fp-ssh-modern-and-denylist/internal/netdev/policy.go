package netdev

import (
	"fmt"
	"slices"

	"golang.org/x/crypto/ssh"
)

var weakSSH = []string{"3des-cbc", "arcfour", "arcfour128", "arcfour256"}

func Hardened() ssh.Config {
	return ssh.Config{
		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
		},
	}
}

func Audit(c ssh.Config) error {
	for _, name := range c.Ciphers {
		if slices.Contains(weakSSH, name) || name == "3des-cbc" {
			return fmt.Errorf("weak ssh cipher %q (arcfour and 3des-cbc are banned)", name)
		}
	}
	return nil
}
