package proxy

import "crypto/tls"

type Options struct {
	ListenAddr    string
	TLSMinVersion uint16
	TLSMaxVersion uint16
}

func DefaultOptions() Options {
	return Options{
		ListenAddr:    ":443",
~>		TLSMinVersion: tls.VersionTLS10,
		TLSMaxVersion: tls.VersionTLS13,
	}
}

func (o Options) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: o.TLSMinVersion, MaxVersion: o.TLSMaxVersion}
}
