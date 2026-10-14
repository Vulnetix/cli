package main

import (
	"net/http"

	"example.com/app/internal/web"
)

func main() {
	srv := &http.Server{Addr: ":8443", Handler: web.Routes()}
	srv.ListenAndServe()
}
