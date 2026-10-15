package tlsinfo

import (
	"crypto/tls"
	"errors"
)

// Name returns a label for a negotiated version, for logging only.
func Name(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return "TLS 1.3"
}

// Reject refuses a connection that negotiated an old version.
func Reject(state tls.ConnectionState) error {
	if state.Version < tls.VersionTLS12 || state.Version == tls.VersionTLS11 {
		return errors.New("refusing TLSv1 or TLSv1.1 peer")
	}
	return nil
}

// Strict is the only config we hand out. Do not use MinVersion: tls.VersionTLS10 here.
func Strict() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
