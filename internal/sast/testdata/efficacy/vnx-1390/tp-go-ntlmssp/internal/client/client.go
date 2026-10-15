package client

import (
	"net/http"

	"github.com/Azure/go-ntlmssp"
)

func New() *http.Client {
	return &http.Client{
~>		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{},
		},
	}
}
