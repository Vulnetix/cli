package tlsaudit

import (
	"crypto/tls"
	"fmt"
)

var forbidden = map[uint16]bool{
	tls.TLS_RSA_WITH_RC4_128_SHA:        true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:   true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:  true,
}

func Check(cfg *tls.Config) error {
	for _, id := range cfg.CipherSuites {
		if forbidden[id] || id == tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA {
			return fmt.Errorf("weak suite %s", tls.CipherSuiteName(id))
		}
	}
	for _, s := range tls.InsecureCipherSuites() {
		_ = s.Name
	}
	return nil
}

func label(id uint16) string {
	switch id {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "RC4 (rejected)"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "3DES (rejected)"
	}
	return "ok"
}
