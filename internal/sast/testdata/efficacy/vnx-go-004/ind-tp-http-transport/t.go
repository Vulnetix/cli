package client

import (
	"crypto/tls"
	"net/http"
)

func New() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
~>			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
