package client

import "crypto/tls"

func Cfg() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
~>	cfg.InsecureSkipVerify = true
	return cfg
}
