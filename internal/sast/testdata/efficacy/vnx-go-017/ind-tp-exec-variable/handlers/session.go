package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
)

func Logout(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
~>		query := fmt.Sprintf("DELETE FROM sessions WHERE token = '%s'", r.FormValue("token"))
		if _, err := db.Exec(query); err != nil {
			http.Error(w, "failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
