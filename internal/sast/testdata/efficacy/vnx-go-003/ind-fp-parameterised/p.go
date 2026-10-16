package repo

import "database/sql"

func Get(db *sql.DB, name string) *sql.Row {
	return db.QueryRow("SELECT id FROM users WHERE name = $1", name)
}
