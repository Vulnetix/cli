package repo

import (
	"database/sql"
	"strings"
)

func In(db *sql.DB, ids []any) (*sql.Rows, error) {
	marks := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	return db.Query("SELECT * FROM t WHERE id IN ("+marks+")", ids...)
}
