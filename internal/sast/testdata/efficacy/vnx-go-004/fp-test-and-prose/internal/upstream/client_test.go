package upstream

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// httptest.NewTLSServer uses a throwaway self-signed certificate.
func TestClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := c.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
}
