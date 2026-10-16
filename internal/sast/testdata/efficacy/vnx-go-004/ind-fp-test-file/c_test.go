package client

import (
	"crypto/tls"
	"testing"
)

func TestX(t *testing.T) {
	_ = &tls.Config{InsecureSkipVerify: true}
}
