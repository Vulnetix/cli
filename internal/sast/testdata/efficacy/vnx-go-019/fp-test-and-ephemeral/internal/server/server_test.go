package server

import (
	"net"
	"net/http"
	_ "net/http/pprof"
	"testing"
)

func TestServe(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, nil)
	go http.ListenAndServe(":6060", nil)
}
