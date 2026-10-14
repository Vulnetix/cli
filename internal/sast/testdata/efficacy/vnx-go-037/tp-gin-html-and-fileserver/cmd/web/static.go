package main

import "net/http"

func static() http.Handler {
~>	return http.StripPrefix("/static/", http.FileServer(http.Dir("public")))
}
