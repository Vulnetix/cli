package handler

import (
	"net/http"
	"strconv"
	"strings"
)

var sortable = map[string]bool{"name": true, "created": true}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	order := "created"
	if s := r.URL.Query().Get("sort"); s != "" {
		if !sortable[s] {
			http.Error(w, "bad sort", http.StatusBadRequest)
			return
		}
		order = s
	}
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	where := `owner = $1`
	args := []any{h.owner}
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		args = append(args, "%"+q+"%")
		where += ` AND name ILIKE $2`
	}
	query := `SELECT id, name FROM items
	WHERE ` + where + `
	ORDER BY "` + order + `" DESC
	LIMIT ` + strconv.Itoa(limit)
	rows, err := h.db.Query(ctx, query, args...)
	if err != nil {
		return
	}
	defer rows.Close()
}
