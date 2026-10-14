package maint

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

var tables = []string{"users", "orders", "sessions"}

// Table names come from a fixed list in this file, and they sit in an
// identifier slot where a bind parameter cannot go.
func Counts(ctx context.Context, db *sql.DB) (map[string]int, error) {
	out := map[string]int{}
	for _, t := range tables {
		var n int
		if err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, t)).Scan(&n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, nil
}

func DropIndex(ctx context.Context, db *sql.DB, name string) error {
	_, err := db.ExecContext(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", pq.QuoteIdentifier(name)))
	return err
}

func CreateDatabase(db *sql.DB, dbName string) error {
	_, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + dbName)
	return err
}

// Only "?" markers are interpolated; the values travel as arguments.
func ByIDs(db *sql.DB, ids []any) (*sql.Rows, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	return db.Query(fmt.Sprintf("SELECT id, name FROM items WHERE id IN (%s)", placeholders), ids...)
}

func Page(db *sql.DB, limit, offset int) (*sql.Rows, error) {
	return db.Query(fmt.Sprintf("SELECT id FROM items ORDER BY id LIMIT %d OFFSET %d", limit, offset))
}
