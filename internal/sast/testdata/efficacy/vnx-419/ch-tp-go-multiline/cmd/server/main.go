package main

import (
	"log"
	"net/http"
)

func main() {
	cfg := loadConfig()
	go func() {
~>		log.Fatal(http.ListenAndServe(
			cfg.AdminListenAddr,
			adminRoutes(),
		))
	}()
	log.Fatal(http.ListenAndServeTLS(cfg.PublicAddr, cfg.Cert, cfg.Key, publicRoutes()))
}
