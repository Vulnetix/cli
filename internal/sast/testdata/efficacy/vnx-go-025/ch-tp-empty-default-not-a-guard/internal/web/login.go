package web

import "net/http"

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := s.authenticate(r); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/dashboard"
	}
~>	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Destroy(r)
~>	w.Header().Set("Location", r.URL.Query().Get("redirect"))
	w.WriteHeader(http.StatusFound)
}
