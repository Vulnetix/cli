package net

import "crypto/tls"

func Old() *tls.Config {
	return &tls.Config{
~>		MinVersion: tls.VersionSSL30, //nolint:staticcheck
	}
}
