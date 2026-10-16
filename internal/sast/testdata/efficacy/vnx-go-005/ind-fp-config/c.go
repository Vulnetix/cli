package web

import "net/http"

type Server struct{ LoginURL string }

func (s *Server) Redir(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.LoginURL, http.StatusFound)
}
