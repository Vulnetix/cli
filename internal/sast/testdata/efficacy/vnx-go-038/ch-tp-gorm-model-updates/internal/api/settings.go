package api

import (
	"encoding/json"
	"net/http"

	"example.com/app/internal/models"
)

func (h *Handler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var patch models.Account
~>	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.db.Model(&models.Account{}).Where("id = ?", id).Updates(&patch).Error; err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
