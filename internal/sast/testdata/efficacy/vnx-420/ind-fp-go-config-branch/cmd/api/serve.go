package main

import (
	"log"
	"net/http"
)

func serve(cfg Config, h http.Handler) {
	if cfg.TLSCert != "" {
		log.Fatal(http.ListenAndServeTLS(cfg.Addr, cfg.TLSCert, cfg.TLSKey, h))
	} else {
		log.Fatal(http.ListenAndServe(cfg.Addr, h))
	}
}
