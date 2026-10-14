package handlers

import (
	"encoding/json"
	"net/http"
)

type createUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (h *H) Create(w http.ResponseWriter, r *http.Request) {
	var in createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.db.Create(&User{Name: in.Name, Email: in.Email, Role: "member"})
}
