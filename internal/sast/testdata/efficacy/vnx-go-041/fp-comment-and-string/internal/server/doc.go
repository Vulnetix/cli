package server

import (
	"crypto/tls"
	"fmt"
)

// Never write MinVersion: tls.VersionTLS10; RFC 8996 deprecates it.
/*
   cfg.MinVersion = tls.VersionTLS11 was removed in 2021.
*/
func warn() {
	fmt.Println("refusing MinVersion: tls.VersionTLS10")
	msg := `MaxVersion = tls.VersionTLS11 is not allowed`
	_ = msg
	_ = &tls.Config{MinVersion: tls.VersionTLS12} // was MinVersion: tls.VersionTLS10
}
