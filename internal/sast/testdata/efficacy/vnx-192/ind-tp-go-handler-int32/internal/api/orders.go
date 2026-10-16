package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func (h *Handler) ListOrders(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pageSize, err := strconv.Atoi(q.Get("page_size"))
	if err != nil {
		http.Error(w, "bad page_size", http.StatusBadRequest)
		return
	}
	offset, err := strconv.ParseInt(q.Get("offset"), 10, 64)
	if err != nil {
		http.Error(w, "bad offset", http.StatusBadRequest)
		return
	}
~>	orders, err := h.repo.List(r.Context(), int32(pageSize), int32(offset))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(orders)
}
