package main

import (
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"
)

const debugAddr = "127.0.0.1:6060"

var listen = flag.String("listen", ":8080", "public listen address")

func main() {
	flag.Parse()
	go func() {
		log.Println(http.ListenAndServe(debugAddr, nil))
	}()
	addr := *listen
	log.Fatal(http.ListenAndServe(addr, nil))
}
