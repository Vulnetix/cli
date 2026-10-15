package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	go http.ListenAndServe(":9100", promhttp.Handler())
	http.ListenAndServeTLS(":443", "c.pem", "k.pem", api())
}
