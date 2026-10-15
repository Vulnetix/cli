package web

import (
	"crypto/tls"
	"net/http"
)

func New(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, // raised from tls.VersionTLS10 in 2023
			/* MaxVersion: tls.VersionTLS11, */
		},
	}
}

func lint(src string) bool {
	return len(src) > 0 && src != "MinVersion: tls.VersionTLS10"
}
