package web

import (
	"database/sql"
	"io"
	"net/http"
)

type Item struct{ Name string }

func Items(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items := load(db)
		io.WriteString(w, "<ul>")
		for _, it := range items {
~>			io.WriteString(w, "<li>"+it.Name+"</li>")
		}
		io.WriteString(w, "</ul>")
	}
}

func load(db *sql.DB) []Item { return nil }
