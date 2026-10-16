package store

import (
	"database/sql"
	"fmt"
)

func ListReports(db *sql.DB, sortColumn string) (*sql.Rows, error) {
	// FIXME: sortColumn comes from the query string, this is an SQL injection
	q := fmt.Sprintf("SELECT id, title FROM reports ORDER BY %s", sortColumn)
	return db.Query(q)
}
