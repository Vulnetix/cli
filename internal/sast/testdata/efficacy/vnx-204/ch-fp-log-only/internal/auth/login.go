package auth

import (
	"log/slog"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	u, err := h.users.ByName(r.Context(), r.FormValue("username"))
	if err != nil {
		slog.Info("login failed: user not found", "user", r.FormValue("username"))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(r.FormValue("password"))) != nil {
		slog.Info("login failed: wrong password", "user", u.ID)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	h.sessions.Start(w, u.ID)
}
