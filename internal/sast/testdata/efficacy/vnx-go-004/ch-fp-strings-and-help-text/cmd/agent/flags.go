package main

import (
	"errors"
	"flag"
)

var insecure = flag.Bool("insecure", false, "skip certificate checks (sets InsecureSkipVerify: true); never use in production")

var usage = `
Agent connects over TLS. Passing --insecure is equivalent to
	&tls.Config{InsecureSkipVerify: true}
`

var errInsecure = errors.New("refusing to start: config.InsecureSkipVerify = true is not allowed with --fips")
