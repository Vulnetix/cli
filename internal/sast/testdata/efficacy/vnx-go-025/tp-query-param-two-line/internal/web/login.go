package web

import (
	"net/http"
)

// After login the user is sent back to wherever ?next= pointed.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := s.authenticate(r); err != nil {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
~>	http.Redirect(w, r, next, http.StatusFound)
}
