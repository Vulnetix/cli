package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	router.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
~>	log.Fatal(http.ListenAndServe(":8000", router))
}
