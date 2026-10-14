package server

import "crypto/tls"

var legacyConf = &tls.Config{
~>	MinVersion: 0x0301,
}

func ssl3() *tls.Config {
	c := new(tls.Config)
~>	c.MinVersion = tls.VersionSSL30 //nolint:staticcheck
	return c
}

func casted() *tls.Config {
	return &tls.Config{
~>		MinVersion:
			uint16(tls.VersionTLS10),
	}
}
