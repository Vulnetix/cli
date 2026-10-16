package web

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func User(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
~>		rows, err := db.Query("SELECT * FROM users WHERE id = " + id)
		if err != nil {
			http.Error(w, "x", 500)
			return
		}
		defer rows.Close()
	}
}
