package netdev

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// Dial connects to old switches that only speak legacy ciphers.
func Dial(addr, user, pass string) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
~>	cfg.Ciphers = append(cfg.Ciphers, "aes128-ctr", "3des-cbc")
	return ssh.Dial("tcp", addr, cfg)
}

func Server() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-gcm@openssh.com",
~>				"arcfour256",
~>				"arcfour",
			},
		},
	}
}
