package client

import (
	"crypto/tls"
	"net/http"
)

func New() *http.Client {
	// HACK: skip TLS verification until the staging cert is fixed
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr}
}
