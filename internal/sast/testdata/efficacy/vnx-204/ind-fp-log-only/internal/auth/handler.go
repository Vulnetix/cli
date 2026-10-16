package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	u, err := s.users.ByEmail(r.Context(), email)
	if errors.Is(err, ErrNoRows) {
		slog.Info("login failed: user not found", "email", email)
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(r.FormValue("password")))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(r.FormValue("password"))) != nil {
		slog.Info("login failed: wrong password", "user", u.ID)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.sessions.Start(w, u.ID)
}
