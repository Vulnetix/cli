package api

import (
	"database/sql"
	"fmt"
	"net/http"
)

type Server struct {
	db *sql.DB
}

// Lookup formats the name into a quoted SQL literal, then runs the text.
func (s *Server) Lookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.URL.Query().Get("name")
~>	q := fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name)
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}

// Logout deletes the session whose token the client sent, formatting it inline.
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Session")
~>	if _, err := s.db.ExecContext(r.Context(), fmt.Sprintf("DELETE FROM sessions WHERE token = '%s'", tok)); err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
	}
}
