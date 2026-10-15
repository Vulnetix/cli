package auth

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	u, err := h.users.ByName(r.Context(), r.FormValue("username"))
	if err != nil {
~>		http.Error(w, "unknown user", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(r.FormValue("password"))) != nil {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	h.sessions.Start(w, u.ID)
}
