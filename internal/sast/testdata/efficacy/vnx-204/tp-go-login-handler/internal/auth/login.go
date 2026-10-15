package auth

import (
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

var (
~>	ErrNoSuchUser    = errors.New("no such user")
	ErrWrongPassword = errors.New("wrong password")
)

func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	u, err := s.users.ByEmail(r.FormValue("email"))
	if err != nil {
~>		http.Error(w, "unknown email address", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(r.FormValue("password"))) != nil {
		http.Error(w, "password is incorrect", http.StatusUnauthorized)
		return
	}
}
