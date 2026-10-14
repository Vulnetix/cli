package webhook

import (
	"crypto/tls"
	"net/http"
)

func Configure(tr *http.Transport) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
~>	cfg.InsecureSkipVerify = true
	tr.TLSClientConfig = cfg
}

func Default() {
	t := http.DefaultTransport.(*http.Transport).Clone()
~>	t.TLSClientConfig.InsecureSkipVerify = true
	http.DefaultTransport = t
}

// A debug switch is not a decision about certificates.
func Debug(tr *http.Transport, debug bool) {
	if debug {
~>		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}
