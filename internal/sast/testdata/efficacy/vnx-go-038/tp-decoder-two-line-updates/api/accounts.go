package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	acct, _ := s.store.Account(r.Context(), userID(r))
	dec := json.NewDecoder(r.Body)
~>	if err := dec.Decode(acct); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.store.Save(r.Context(), acct); err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
	}
}
