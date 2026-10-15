package main

import (
	"log"
	"net"
)

func main() {
	port := "9000"
~>	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatal(err)
	}
	serve(ln)
}
