package web

import (
	"database/sql"
	"fmt"
	"net/http"
)

func Comments(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query("SELECT body FROM comments")
		defer rows.Close()
		for rows.Next() {
			var body string
			rows.Scan(&body)
~>			fmt.Fprintf(w, "<li>%s</li>", body)
		}
	}
}
