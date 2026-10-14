package policy

import (
	"crypto/tls"
	"errors"
	"slices"
)

var banned = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var modern = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func Validate(cfg *tls.Config) error {
	for _, id := range cfg.CipherSuites {
		if slices.Contains(banned, id) {
			return errors.New("banned cipher suite")
		}
	}
	return nil
}

func Harden(cfg *tls.Config) {
	cfg.CipherSuites = modern
}
