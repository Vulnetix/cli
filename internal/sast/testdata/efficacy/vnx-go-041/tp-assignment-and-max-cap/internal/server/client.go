package server

import (
	ctls "crypto/tls"
	"net/http"
)

func transport() *http.Transport {
	cfg := &ctls.Config{}
~>	cfg.MinVersion = ctls.VersionTLS11
	return &http.Transport{TLSClientConfig: cfg}
}

func pinned() *ctls.Config {
	return &ctls.Config{
~>		MinVersion: ctls.VersionTLS10,
~>		MaxVersion: ctls.VersionTLS11,
	}
}
