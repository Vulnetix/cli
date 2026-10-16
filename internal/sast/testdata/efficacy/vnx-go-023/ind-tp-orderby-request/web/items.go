package web

import (
	"database/sql"
	"net/http"
)

func Items(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sort := r.URL.Query().Get("sort")
~>		rows, err := db.Query("SELECT id FROM items ORDER BY " + sort)
		if err != nil {
			http.Error(w, "bad", 500)
			return
		}
		defer rows.Close()
	}
}
