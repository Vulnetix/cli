package api

import (
	"net/http"
	"strconv"
)

const maxPage = 500

func page(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.Atoi(r.URL.Query().Get("size"))
	if err != nil || size <= 0 || size > maxPage {
		http.Error(w, "bad size", http.StatusBadRequest)
		return
	}
	rows := make([]Row, 0, size)
	writeJSON(w, rows)
}
