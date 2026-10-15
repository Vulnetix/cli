package client

import (
	"crypto/tls"
	"net/http"
)

func New(cfg Config) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}}
~>	// if cfg.Insecure && cfg.Env == "production" {
	// 	return nil
	// }
	// tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	return &http.Client{Transport: tr}
}
