package main

import (
	"log"
	"net"
	"os"
	"strconv"
)

func main() {
	raw := os.Getenv("LISTEN_PORT")
	p, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
~>	port := uint16(p)
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	serve(ln)
}
