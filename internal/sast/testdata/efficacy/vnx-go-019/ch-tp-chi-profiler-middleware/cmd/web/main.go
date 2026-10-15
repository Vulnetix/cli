package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Mount("/debug", middleware.Profiler())
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
~>	http.ListenAndServe(":3000", r)
}
