package client

import "crypto/tls"

func Cfg() *tls.Config { return &tls.Config{InsecureSkipVerify: false} }
