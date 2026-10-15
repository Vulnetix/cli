package main

import (
	"flag"
	"log"
	"net"
	"net/http"
)

const mgmtListen = "[::1]:7000"

func main() {
	adminAddr := "localhost:6060"
	debugAdmin := flag.String("admin-addr", "127.0.0.1:9001", "admin listen address")
	flag.Parse()
	go func() {
		log.Fatal(http.ListenAndServe(adminAddr, adminMux()))
	}()
	go func() {
		log.Fatal(http.ListenAndServe(*debugAdmin, adminMux()))
	}()
	ln, err := net.Listen("tcp", mgmtListen)
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, mgmtMux())
	log.Fatal(http.ListenAndServeTLS(":443", "c.pem", "k.pem", publicMux()))
}
