package transport

import (
	"crypto/tls"
	"net/http"
	"os"
)

type Options struct {
	SkipVerify bool
	CAFile     string
}

func Build(o Options) *http.Transport {
	cfg := &tls.Config{InsecureSkipVerify: o.SkipVerify}
	if os.Getenv("NATS_TLS_INSECURE") == "true" {
		cfg.InsecureSkipVerify = os.Getenv("NATS_TLS_INSECURE") == "true"
	}
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS13}}
}
