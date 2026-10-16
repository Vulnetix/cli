package auth

import (
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	u, err := s.users.ByEmail(r.Context(), email)
	if errors.Is(err, ErrNoRows) {
~>		http.Error(w, "unknown user", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(password)) != nil {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	s.sessions.Start(w, u.ID)
}
