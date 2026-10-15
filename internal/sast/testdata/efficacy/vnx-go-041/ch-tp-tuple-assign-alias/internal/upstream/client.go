package upstream

import (
	"net/http"

	gotls "crypto/tls"
)

func NewTransport(insecureLegacy bool) *http.Transport {
	tc := new(gotls.Config)
	if insecureLegacy {
~>		tc.MinVersion, tc.MaxVersion = gotls.VersionSSL30, gotls.VersionTLS13
	}
	return &http.Transport{
		TLSClientConfig: tc,
	}
}

func NewStrict() *http.Transport {
	tc := &gotls.Config{}
	tc.MinVersion, tc.MaxVersion = gotls.VersionTLS12, gotls.VersionTLS13
	return &http.Transport{TLSClientConfig: tc}
}
