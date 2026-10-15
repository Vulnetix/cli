package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
~>	json.NewEncoder(w).Encode(map[string]string{"email": u.Email, "password_hash": u.PasswordHash})
}
