package http

import (
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func Routes(h *Handlers) *chi.Mux {
	r := chi.NewRouter()
	r.With(httprate.LimitByIP(5, time.Minute)).Post("/login", h.Login)
	return r
}
