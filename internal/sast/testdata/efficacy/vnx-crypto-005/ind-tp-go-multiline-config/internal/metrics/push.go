package metrics

import (
	"crypto/tls"
	"net/http"
	"time"
)

func newPushClient() *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
~>		InsecureSkipVerify: true,
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}
