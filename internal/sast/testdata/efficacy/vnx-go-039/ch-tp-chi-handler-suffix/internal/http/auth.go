package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (s *Server) routes(r chi.Router) {
	r.Post("/v1/session", s.LoginHandler)
}

~>func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !s.users.Check(r.Context(), in.Email, in.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.issue(w, in.Email)
}
