package web

import (
	"database/sql"
	"net/http"
	"strconv"
)

func User(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT id FROM users WHERE name = $1", name)
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	db.Query("SELECT name FROM users WHERE id = " + strconv.Itoa(id))
}
