package http

import (
	"database/sql"
	"net/http"
)

type Server struct {
	db *sql.DB
}

func (s *Server) Signup(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	pw := r.PostFormValue("password")
~>	_, err := s.db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", email, pw)
	if err != nil {
		http.Error(w, "signup failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) Reset(w http.ResponseWriter, r *http.Request, u *User) {
~>	u.Password = r.FormValue("new_password")
	s.saveUser(u)
}
