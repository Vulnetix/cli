package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

const debugAddr = ":6060"

func main() {
	go func() {
~>		log.Println(http.ListenAndServe(debugAddr, nil))
	}()
	select {}
}
