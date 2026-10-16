package client

import (
	"crypto/tls"
	"flag"
)

var insecure = flag.Bool("insecure", false, "skip verify")

func Cfg() *tls.Config {
	return &tls.Config{InsecureSkipVerify: *insecure}
}
