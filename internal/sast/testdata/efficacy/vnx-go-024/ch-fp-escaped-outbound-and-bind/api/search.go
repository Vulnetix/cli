package api

import (
	"database/sql"
	"net/http"
	"net/url"
)

type Server struct{ db *sql.DB }

func (s *Server) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	resp, err := http.Get("https://search.internal/api?q=" + url.QueryEscape(q))
	if err == nil {
		resp.Body.Close()
	}
	rows, err := s.db.QueryContext(r.Context(), "SELECT id FROM docs WHERE title ILIKE $1", "%"+q+"%")
	if err == nil {
		rows.Close()
	}
}
