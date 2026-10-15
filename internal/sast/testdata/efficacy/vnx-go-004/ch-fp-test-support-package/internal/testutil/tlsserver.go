package testutil

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
)

// NewTLSServer starts a server with a self-signed certificate and a client
// that trusts it; only the test suite imports this package.
func NewTLSServer(h http.Handler) (*httptest.Server, *http.Client) {
	srv := httptest.NewTLSServer(h)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	return srv, c
}
