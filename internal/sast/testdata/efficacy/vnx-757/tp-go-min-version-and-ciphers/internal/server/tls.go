package server

import "crypto/tls"

func legacyConfig() *tls.Config {
	return &tls.Config{
~>		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			@@sample:t[l]s[.][T]LS[_]EC[D]HE[_]RS[A][_]W[I]TH[_]AE[S][_]1[2]8[_][G]CM[_]SH[A]25[6]@@,
~>			@@sample:t[l]s[.][T]LS[_]RS[A][_]W[I]TH[_]RC[4][_]1[2]8[_][S]HA@@,
~>			@@sample:t[l]s[.][T]LS[_]EC[D]HE[_]RS[A][_]W[I]TH[_]3D[E]S[_][E]DE[_]CB[C][_]S[H]A@@,
		},
	}
}

func capped(cfg *tls.Config) {
~>	cfg.MaxVersion = tls.VersionTLS11
~>	cfg.MinVersion = tls.VersionSSL30
}
