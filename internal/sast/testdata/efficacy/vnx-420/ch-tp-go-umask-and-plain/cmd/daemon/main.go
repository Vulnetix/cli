package main

import (
	"net"
	"net/http"
	"syscall"
)

func control() (net.Listener, error) {
~>	old := syscall.Umask(0)
	defer syscall.Umask(old)
	return net.Listen("unix", "/var/run/daemon.sock")
}

func main() {
	go func() {
~>		_ = http.ListenAndServe("0.0.0.0:8080", appRouter())
	}()
	_ = http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", appRouter())
}
