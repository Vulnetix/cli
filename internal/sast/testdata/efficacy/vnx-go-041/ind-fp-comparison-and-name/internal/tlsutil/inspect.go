package tlsutil

import (
	"crypto/tls"
	"fmt"
)

// Rejecting tls.VersionTLS10 handshakes is done below; do not set MinVersion: tls.VersionTLS10.
func Check(state tls.ConnectionState) error {
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		return fmt.Errorf("legacy protocol")
	}
	switch state.Version {
	case tls.VersionTLS10:
		return fmt.Errorf("tls1.0")
	}
	msg := "MinVersion: tls.VersionTLS10 is forbidden"
	_ = msg
	return nil
}

var names = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}
