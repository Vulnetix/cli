package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

// pprof stays on loopback; the public listener uses its own mux, so the
// default mux (and /debug/pprof/) is not reachable from outside.
func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	go http.ListenAndServe("127.0.0.1:6061", http.DefaultServeMux)
	go http.ListenAndServe("[::1]:6062", nil)
	api := http.NewServeMux()
	api.HandleFunc("/jobs", jobs)
	srv := &http.Server{
		Addr:    ":8080",
		Handler: api,
	}
	log.Fatal(srv.ListenAndServe())
}

func jobs(w http.ResponseWriter, r *http.Request) {}
