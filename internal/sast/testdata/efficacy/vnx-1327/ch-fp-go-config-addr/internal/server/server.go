package server

import "net/http"

type Config struct {
	Addr string
}

func New(cfg Config, h http.Handler) *http.Server {
	// default to "0.0.0.0:8080" in the helm chart, never here
	return &http.Server{Addr: cfg.Addr, Handler: h}
}
