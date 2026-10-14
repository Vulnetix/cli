package api

import "net/http"

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	s.auth.RequireRole(w, r, "admin")
	s.auth.RequireRole(w, r, "owner")
	id := r.PathValue("id")
	if s.isOwner(r, id) && s.isOwner(r, r.FormValue("target")) {
		s.store.Delete(id)
	} else if s.isAdmin(r) {
		s.store.Archive(id)
	} else if s.isOwner(r, "root") {
		s.store.Lock(id)
	}
	if err := s.audit(r); err != nil {
		return
	}
	if err := s.audit(r); err != nil {
		return
	}
}
