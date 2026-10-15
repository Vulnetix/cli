package api

import (
	"net/http"
	"strconv"
)

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		http.Error(w, "bad limit", http.StatusBadRequest)
		return
	}
~>	rows := h.store.Page(int32(limit))
	_ = rows
}
