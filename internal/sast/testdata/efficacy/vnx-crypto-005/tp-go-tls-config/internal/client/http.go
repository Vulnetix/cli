package client

import (
	"crypto/tls"
	"net/http"
)

func NewClient() *http.Client {
	tr := &http.Transport{
~>		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

func Config() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
~>	cfg.InsecureSkipVerify = true
	return cfg
}

func Aligned() *tls.Config {
	return &tls.Config{
~>		InsecureSkipVerify:   true, // #nosec G402
		MinVersion:           tls.VersionTLS12,
	}
}
