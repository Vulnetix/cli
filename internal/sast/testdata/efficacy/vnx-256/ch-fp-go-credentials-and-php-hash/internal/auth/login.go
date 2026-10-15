package auth

import "net/http"

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	creds := Credentials{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}
	if !h.svc.Verify(creds) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}
}
