package api

import (
	"encoding/json"
	"net/http"
)

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
}

func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	u, _ := s.store.UserByID(r.Context(), r.PathValue("id"))
	json.NewEncoder(w).Encode(u)
}
