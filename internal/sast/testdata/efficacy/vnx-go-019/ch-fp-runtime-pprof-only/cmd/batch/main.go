package main

import (
	"log"
	"net/http"
	"os"
	"runtime/pprof"
)

func main() {
	f, _ := os.Create("cpu.prof")
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("hi")) })
	log.Fatal(http.ListenAndServe(":8080", nil))
}
