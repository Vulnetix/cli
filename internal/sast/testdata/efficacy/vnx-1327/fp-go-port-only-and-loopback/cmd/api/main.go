package main

import (
	"net"
	"net/http"
	"os"
)

func main() {
	go http.ListenAndServe("127.0.0.1:6060", nil)
	ln, _ := net.Listen("tcp", "localhost:9000")
	defer ln.Close()
	addr := os.Getenv("ADDR")
	_ = http.ListenAndServe(addr, nil)
}
