package server

import (
	"crypto/tls"
	"log"
)

func modernConfig() *tls.Config {
	// MinVersion: tls.VersionTLS10 was the old default; do not go back.
	log.Println("refusing tls.VersionTLS10 clients")
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			@@sample:t[l]s[.][T]LS[_]EC[D]HE[_]EC[D]SA[_]WI[T]H[_][A]ES[_]25[6][_]G[C]M[_][S]HA[3]84@@,
			@@sample:t[l]s[.][T]LS[_]EC[D]HE[_]RS[A][_]W[I]TH[_]CH[A]CH[A]20[_]PO[L]Y1[3]05[_]SH[A]25[6]@@,
		},
	}
}

var names = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}

func isLegacy(v uint16) bool {
	return v == tls.VersionTLS10 || v < tls.VersionTLS12
}
