package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/pprof"
)

var debugAddr = flag.String("debug-addr", "", "address for the debug listener")

func main() {
	flag.Parse()
	go func() { log.Println(http.ListenAndServe(*debugAddr, nil)) }()

	dbg := http.NewServeMux()
	dbg.HandleFunc("/debug/pprof/", pprof.Index)
	go http.ListenAndServe("127.0.0.1:6061", dbg)

	api := http.NewServeMux()
	api.HandleFunc("/v1/items", func(w http.ResponseWriter, _ *http.Request) {})
	srv := &http.Server{Addr: ":8080", Handler: api}
	log.Fatal(srv.ListenAndServe())
}
