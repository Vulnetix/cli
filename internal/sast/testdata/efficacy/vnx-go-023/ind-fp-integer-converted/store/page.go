package store

import (
	"database/sql"
	"strconv"
)

func Page(db *sql.DB, limit, offset int) (*sql.Rows, error) {
	return db.Query("SELECT id FROM items LIMIT " + strconv.Itoa(limit) + " OFFSET " + strconv.Itoa(offset))
}
