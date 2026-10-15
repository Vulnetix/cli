package main

import (
	"log"
	"net/http"

	"golang.org/x/sync/errgroup"
)

func main() {
	r := router()
	var g errgroup.Group
	g.Go(func() error {
~>		return http.ListenAndServe(":8080", r)
	})
	g.Go(func() error {
		return http.ListenAndServeTLS(":8443", "tls.crt", "tls.key", r)
	})
	log.Fatal(g.Wait())
}

func legacy(r http.Handler) {
	go http.ListenAndServeTLS(":9443", "tls.crt", "tls.key", r)
~>	log.Fatal(http.ListenAndServe(":9080", r))
}
