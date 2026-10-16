package main

import (
	"log"
	"net"
	"net/http"
)

func main() {
~>	ln, err := net.Listen("tcp", "0.0.0.0:9090")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(ln, nil))
}
