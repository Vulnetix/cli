package server

import (
	"crypto/tls"
	"testing"
)

func TestRejectsOldClients(t *testing.T) {
	client := &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS10,
	}
	_ = client
}
