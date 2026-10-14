package netx

import "crypto/tls"

type Options struct {
	MinVersion uint16
}

func build(o Options, legacy bool) *tls.Config {
	minVer := uint16(tls.VersionTLS10)
	minVer = tls.VersionTLS12
	cfg := &tls.Config{
		MinVersion: minVer,
		MaxVersion: o.MinVersion,
	}
	floor := o.MinVersion
	cfg.MinVersion = floor
	return cfg
}

var supported = []uint16{tls.VersionTLS12, tls.VersionTLS13}
