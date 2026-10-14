package search

import (
	"database/sql"
	"strings"
)

func Titles(db *sql.DB, term string) (*sql.Rows, error) {
~>	q := "SELECT id, title FROM posts WHERE title LIKE '%" + term + "%'"
	return db.Query(q)
}

// Joining raw strings with quotes is not a parameter list.
func ByIDs(db *sql.DB, ids []string) (*sql.Rows, error) {
~>	q := "SELECT id FROM posts WHERE id IN ('" + strings.Join(ids, "','") + "')"
	return db.Query(q)
}

// The clause has no statement keyword of its own, but its variable is run.
func Mine(db *sql.DB, owner, tag string) (*sql.Rows, error) {
	q := "SELECT id FROM posts WHERE deleted = false"
	if owner != "" {
~>		q += " AND owner = '" + owner + "'"
	}
	if tag != "" {
~>		q = q + " AND tag=" + tag
	}
	return db.Query(q)
}
