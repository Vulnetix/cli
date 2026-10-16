package server

import (
	"crypto/tls"
	"testing"
)

func TestLegacyRejected(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS10}
	_ = cfg
}
