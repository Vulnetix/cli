package handlers

import (
	"encoding/json"
	"net/http"
)

func (h *Profiles) Save(w http.ResponseWriter, req *http.Request) {
	profile := &Profile{}
~>	err := json.NewDecoder(req.Body).
		Decode(profile)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	profile.UpdatedBy = currentUser(req)
	if err := h.repo.Update(
		req.Context(),
		profile,
	); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
