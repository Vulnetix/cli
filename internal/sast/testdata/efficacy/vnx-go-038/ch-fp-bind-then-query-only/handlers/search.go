package handlers

import (
	"encoding/json"
	"net/http"
)

type filter struct {
	Email string `json:"email"`
	Limit int    `json:"limit"`
}

func (h *Users) Search(w http.ResponseWriter, r *http.Request) {
	var f filter
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var users []User
	h.db.Where("email = ?", f.Email).Limit(f.Limit).Find(&users)
	h.audit.Create(r.Context(), "user.search", f.Email)
	_ = json.NewEncoder(w).Encode(users)
}
