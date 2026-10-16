package main

import (
	"log"
	"os"
	"strconv"
)

func main() {
	p, err := strconv.ParseUint(os.Getenv("LISTEN_PORT"), 10, 16)
	if err != nil {
		log.Fatal(err)
	}
	port := uint16(p)

	w, err := strconv.ParseInt(os.Getenv("WORKERS"), 10, 32)
	if err != nil {
		log.Fatal(err)
	}
	workers := int32(w)
	start(port, workers)
}
