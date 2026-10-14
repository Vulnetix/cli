package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

// The address comes from the deployment; the rule cannot see what it is.
func main() {
	addr := os.Getenv("DEBUG_ADDR")
	go http.ListenAndServe(addr, nil)
	// Never do this in production: http.ListenAndServe(":6060", nil)
	msg := "pprof is served by http.ListenAndServe(\":6060\", nil) in dev builds"
	log.Println(msg)
}
