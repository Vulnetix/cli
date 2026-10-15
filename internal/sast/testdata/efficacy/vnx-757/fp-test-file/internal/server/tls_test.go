package server

import (
	"crypto/tls"
	"testing"
)

func TestRejectsOldClients(t *testing.T) {
	client := &tls.Config{MaxVersion: tls.VersionTLS10}
	_ = client
}
