package edge

import (
	"github.com/traefik/traefik/v3/pkg/tls"
)

// LegacyOptions serves the kiosk fleet that cannot be upgraded.
func LegacyOptions() map[string]tls.Options {
	return map[string]tls.Options{
		"kiosk": {
~>			MinVersion:   "VersionTLS10",
			CipherSuites: []string{"@@sample:T[L]S[_][E]CD[H]E[_][R]SA[_]WI[T]H[_][A]ES[_]12[8][_]C[B]C[_][S]HA@@"},
		},
		"default": {
			MinVersion: "VersionTLS12",
		},
	}
}
