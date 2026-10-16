package main

import (
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	addr := flag.String("debug-addr", "127.0.0.1:6060", "pprof listen address")
	flag.Parse()
	// Never bind ":6060" here; the address comes from the flag.
	log.Fatal(http.ListenAndServe(*addr, nil))
}
