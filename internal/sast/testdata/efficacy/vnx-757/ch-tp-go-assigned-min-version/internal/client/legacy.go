package client

import (
	"crypto/tls"
	"net/http"
)

// NewLegacyClient talks to the old billing gateway.
func NewLegacyClient() *http.Client {
	cfg := &tls.Config{}
~>	cfg.MinVersion = tls.VersionTLS10
	cfg.CipherSuites = []uint16{
		@@sample:t[l]s[.][T]LS[_]EC[D]HE[_]RS[A][_]W[I]TH[_]AE[S][_]1[2]8[_][G]CM[_]SH[A]25[6]@@,
~>		@@sample:t[l]s[.][T]LS[_]RS[A][_]W[I]TH[_]3D[E]S[_][E]DE[_]CB[C][_]S[H]A@@,
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func grpcConfig() *tls.Config {
~>	return &tls.Config{MinVersion: tls.VersionSSL30, ServerName: "rpc.internal"}
}
