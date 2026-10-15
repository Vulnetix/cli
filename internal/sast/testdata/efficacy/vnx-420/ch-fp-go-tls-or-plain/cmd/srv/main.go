package main

import (
	"log"
	"net/http"
)

func run(cfg Config, h http.Handler) error {
	srv := &http.Server{Addr: cfg.Addr, Handler: h}
	if cfg.CertFile != "" {
		return srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	} else {
		return http.ListenAndServe(cfg.Addr, h)
	}
}

func serve(cfg Config, h http.Handler) {
	if cfg.Insecure {
		log.Fatal(http.ListenAndServe(cfg.Addr, h))
	}
	log.Fatal(http.ListenAndServeTLS(cfg.Addr, cfg.CertFile, cfg.KeyFile, h))
}
