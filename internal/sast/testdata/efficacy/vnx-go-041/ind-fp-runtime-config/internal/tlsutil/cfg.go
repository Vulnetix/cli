package tlsutil

import "crypto/tls"

func FromSettings(minVer uint16, opts map[string]uint16) *tls.Config {
	c := &tls.Config{MinVersion: minVer}
	c.MaxVersion = opts["max"]
	if minVer < tls.VersionTLS12 {
		c.MinVersion = tls.VersionTLS12
	}
	return c
}
