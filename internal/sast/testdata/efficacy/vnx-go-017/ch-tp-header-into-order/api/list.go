package api

import (
	"database/sql"
	"fmt"
	"net/http"
)

type Handler struct{ DB *sql.DB }

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	sortCol := r.Header.Get("X-Sort")
~>	rows, err := h.DB.Query(fmt.Sprintf("SELECT id, title FROM posts ORDER BY %s", sortCol))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
