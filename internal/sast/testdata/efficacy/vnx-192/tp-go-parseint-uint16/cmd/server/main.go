package main

import (
	"os"
	"strconv"
)

func main() {
	v, _ := strconv.ParseInt(os.Getenv("PORT"), 10, 64)
~>	port := uint16(v)
	n, _ := strconv.ParseInt(os.Getenv("WORKERS"), 10, 32)
~>	workers := uint32(n)
	listen(port, workers)
}
