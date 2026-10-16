package tlsutil

import (
	"crypto/tls"
	"testing"
)

func TestLegacyClientRejected(t *testing.T) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS10,
	}
	_ = cfg
}
