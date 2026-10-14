package registry

import (
	"crypto/tls"
	"net/http"
	"os"
)

type Options struct {
	// InsecureSkipVerify disables certificate checks for a registry the
	// operator names with --insecure-registry.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	Insecure           bool
}

func Transport(o Options) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: o.InsecureSkipVerify},
	}
}

func FromEnv() *tls.Config {
	return &tls.Config{InsecureSkipVerify: os.Getenv("REGISTRY_INSECURE") == "1"}
}

func Strict() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12}
}

// The flag is the operator's explicit, per-run choice (like curl -k).
func Apply(tr *http.Transport, o Options) {
	if o.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if o.InsecureSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
}
