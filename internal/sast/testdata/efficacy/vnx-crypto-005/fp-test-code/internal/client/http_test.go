package client

import (
	"crypto/tls"
	"testing"
)

func TestTLS(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	_ = cfg
}
