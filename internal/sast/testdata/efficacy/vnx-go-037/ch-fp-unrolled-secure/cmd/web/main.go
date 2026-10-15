package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/unrolled/secure"
)

var pages = template.Must(template.ParseGlob("templates/*.html"))

func main() {
	sec := secure.New(secure.Options{
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		ContentSecurityPolicy: "default-src 'self'",
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = pages.ExecuteTemplate(w, "index.html", nil)
	})
	log.Fatal(http.ListenAndServe(":8080", sec.Handler(mux)))
}
