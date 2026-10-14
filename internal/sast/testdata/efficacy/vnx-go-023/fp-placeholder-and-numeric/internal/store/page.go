package store

import (
	"database/sql"
	"strconv"
)

// Placeholder numbers and integers converted to text cannot carry SQL.
func Page(db *sql.DB, owner string, limit, offset int, n int) (*sql.Rows, error) {
	q := "SELECT id FROM notes WHERE owner = $" + strconv.Itoa(n) +
		" LIMIT " + strconv.Itoa(limit) + " OFFSET " + strconv.Itoa(offset)
	return db.Query(q, owner)
}

func ByID(db *sql.DB, id int64) (*sql.Rows, error) {
	return db.Query("SELECT body FROM notes WHERE id = " + strconv.FormatInt(id, 10))
}

func ByOwner(db *sql.DB, owner string) (*sql.Rows, error) {
	return db.Query("SELECT id FROM notes WHERE owner = ? AND deleted = 0", owner)
}
