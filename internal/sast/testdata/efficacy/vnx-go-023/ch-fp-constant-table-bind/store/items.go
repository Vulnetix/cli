package store

import (
	"database/sql"
	"strconv"
)

const itemsTable = "items"

func Get(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM "+itemsTable+" WHERE id = ?", id)
}

func Page(db *sql.DB, limit int) (*sql.Rows, error) {
	return db.Query("SELECT * FROM items ORDER BY id LIMIT " + strconv.Itoa(limit))
}
