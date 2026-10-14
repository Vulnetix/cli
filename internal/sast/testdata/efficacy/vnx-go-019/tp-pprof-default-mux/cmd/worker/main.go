package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	go func() {
		// /debug/pprof/ is on the default mux and this serves it to every
		// interface: heap, goroutine stacks and the command line.
~>		log.Println(http.ListenAndServe(":6060", nil))
	}()
	run()
}

func run() {
	srv := &http.Server{
~>		Addr: "0.0.0.0:7070",
	}
	log.Fatal(srv.ListenAndServe())
}
