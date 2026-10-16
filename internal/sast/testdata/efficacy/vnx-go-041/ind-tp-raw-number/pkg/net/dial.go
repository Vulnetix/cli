package net

import (
	"crypto/tls"
	"net"
)

func Dial(addr string) (net.Conn, error) {
	return tls.Dial("tcp", addr, &tls.Config{
~>		MinVersion: 0x0301,
	})
}
