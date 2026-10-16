package client

import "crypto/tls"

var conf = &tls.Config{
	ServerName: "internal.example.com",
~>	InsecureSkipVerify: true,
}
