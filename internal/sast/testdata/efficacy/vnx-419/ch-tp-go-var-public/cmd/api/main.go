package main

import (
	"log"
	"net"
	"net/http"
	"os"
)

const mgmtAddr = "0.0.0.0:8086"

func main() {
	adminAddr := ":9001"
	if v := os.Getenv("ADMIN_ADDR"); v != "" {
		adminAddr = v
	}
	go func() {
~>		log.Fatal(http.ListenAndServe(adminAddr, nil))
	}()
~>	ln, err := net.Listen("tcp", mgmtAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(ln, nil))
}
