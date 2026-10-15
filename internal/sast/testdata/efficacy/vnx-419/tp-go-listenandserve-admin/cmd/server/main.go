package main

import (
	"log"
	"net/http"
)

func main() {
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/users", listUsers)
	go func() {
~>		log.Fatal(http.ListenAndServe(":9090", adminMux))
	}()
~>	if err := http.ListenAndServe(cfg.AdminAddr, nil); err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServeTLS(":443", "cert.pem", "key.pem", publicMux))
}
