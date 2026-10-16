package server

import "net/http"

type Handler struct{}

~>func (h *Handler) Authenticate(w http.ResponseWriter,
	r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
