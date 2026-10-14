package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func (s *Server) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	var in profileInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if err := in.Validate(); err != nil {
		writeError(w, err)
		return
	}
	updated, err := s.users.UpdateProfile(r.Context(), user.ID, in)
	if errors.Is(err, ErrConflict) {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	if err != nil {
		s.log.Error("update profile", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit.Record(r.Context(), user.ID, "profile.update")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}
