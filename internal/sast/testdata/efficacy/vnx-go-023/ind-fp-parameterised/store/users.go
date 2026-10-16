package store

import "database/sql"

func Get(db *sql.DB, userID string) *sql.Row {
	return db.QueryRow("SELECT id, name FROM users WHERE id = ?", userID)
}

func Names(db *sql.DB, a, b string) (*sql.Rows, error) {
	return db.Query("SELECT name FROM users WHERE name IN (?, ?)", a, b)
}
