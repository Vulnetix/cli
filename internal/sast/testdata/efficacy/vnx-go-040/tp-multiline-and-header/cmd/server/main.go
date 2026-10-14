package main

import (
	"log"
	"net/http"
)

func debug(cfg Config, r *http.Request) {
~>	logger.Infof("config loaded: dsn=%s token=%s",
		cfg.DSN,
		cfg.APIToken)
~>	log.Printf("request auth header: %s", r.Header.Get("Authorization"))
}
