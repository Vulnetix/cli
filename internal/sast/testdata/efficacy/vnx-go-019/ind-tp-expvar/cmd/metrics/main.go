package main

import (
	"expvar"
	"log"
	"net/http"
)

var hits = expvar.NewInt("hits")

func main() {
	hits.Add(1)
~>	log.Fatal(http.ListenAndServe(":8081", nil))
}
