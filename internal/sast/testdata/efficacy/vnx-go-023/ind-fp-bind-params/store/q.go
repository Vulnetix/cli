package store

import (
	"database/sql"
	"strconv"
	"strings"
)

func Search(db *sql.DB, n int, v any, clauses []string) {
	db.Query("SELECT id FROM t WHERE a = $"+strconv.Itoa(n), v)
	q := "SELECT id FROM t" + " WHERE " + strings.Join(clauses, " AND ")
	_ = q
}
