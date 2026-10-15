package client

import (
	"crypto/tls"
	"net/http"
)

func New() *http.Client {
	conf := &tls.Config{}
~>	conf.InsecureSkipVerify = true
	return &http.Client{Transport: &http.Transport{TLSClientConfig: conf}}
}

func Other() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
~>		InsecureSkipVerify: true, // nolint:gosec
	}
}
