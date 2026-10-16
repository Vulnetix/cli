package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	go func() {
		log.Println(http.ListenAndServe("127.0.0.1:6061", nil))
	}()
	select {}
}
