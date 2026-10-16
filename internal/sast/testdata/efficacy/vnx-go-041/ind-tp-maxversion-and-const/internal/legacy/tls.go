package legacy

import "crypto/tls"

const oldest = tls.VersionTLS10

func Pinned() *tls.Config {
	return &tls.Config{
~>		MinVersion: oldest,
~>		MaxVersion: tls.VersionTLS11,
	}
}
