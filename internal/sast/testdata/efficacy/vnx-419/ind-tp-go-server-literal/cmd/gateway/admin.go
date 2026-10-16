package main

import (
	"log"
	"net/http"
)

func startAdmin(cfg Config, adminRouter http.Handler) {
	srv := &http.Server{
		Addr:    cfg.AdminAddr,
		Handler: adminRouter,
	}
	go func() {
~>		if err := srv.ListenAndServe(); err != nil {
			log.Printf("admin server: %v", err)
		}
	}()
}

func startMgmt(cfg Config, mux *http.ServeMux) {
~>	log.Fatal(http.ListenAndServe(cfg.ManagementListen, mux))
}
