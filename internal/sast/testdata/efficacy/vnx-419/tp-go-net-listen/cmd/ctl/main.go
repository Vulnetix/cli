package main

import (
	"net"
	"net/http"
)

func serveControl(adminPort string) error {
~>	ln, err := net.Listen("tcp", ":"+adminPort)
	if err != nil {
		return err
	}
	return http.Serve(ln, controlHandler())
}
