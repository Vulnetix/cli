package client

import (
	gotls "crypto/tls"
	"net/http"
)

func New() *http.Client {
	cfg := &gotls.Config{}
	cfg.ServerName = "api.internal"
~>	cfg.MinVersion = gotls.VersionTLS11
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}
