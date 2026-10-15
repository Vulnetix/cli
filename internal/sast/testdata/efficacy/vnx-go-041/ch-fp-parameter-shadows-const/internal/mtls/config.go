package mtls

import "crypto/tls"

// floor is what we refuse to go below; anything older is rejected.
const floor = tls.VersionTLS11

func Validate(v uint16) bool { return v > floor }

func New(minVersion uint16) *tls.Config {
	if minVersion <= floor {
		minVersion = tls.VersionTLS12
	}
	return &tls.Config{MinVersion: minVersion}
}
