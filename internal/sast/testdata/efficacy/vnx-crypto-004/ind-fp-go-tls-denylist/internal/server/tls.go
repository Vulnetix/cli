package server

import (
	"crypto/des"
	"crypto/tls"
)

// insecureSuites lists suites we refuse even if a client offers them.
var insecureSuites = []uint16{
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
}

// legacyBlock is only used to size buffers for a protocol field.
const legacyBlock = des.BlockSize

func serverConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
