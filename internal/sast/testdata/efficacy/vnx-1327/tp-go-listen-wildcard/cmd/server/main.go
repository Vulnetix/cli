package main

import (
	"log"
	"net"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func main() {
~>	ln, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, nil)

	srv := &http.Server{
~>		Addr:    "0.0.0.0:8443",
		Handler: http.DefaultServeMux,
	}
	go srv.ListenAndServeTLS("cert.pem", "key.pem")

	app := fiber.New()
~>	log.Fatal(app.Listen("[::]:80"))
}
