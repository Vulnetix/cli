package users

import "net/http"

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	u := &models.User{
		Email:    r.FormValue("email"),
~>		Password: r.FormValue("password"),
	}
	if err := h.db.Create(u).Error; err != nil {
		http.Error(w, "could not register", http.StatusInternalServerError)
	}
}
