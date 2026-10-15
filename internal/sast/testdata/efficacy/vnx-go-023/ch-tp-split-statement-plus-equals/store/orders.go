package store

import (
	"context"
	"database/sql"
)

func Orders(ctx context.Context, db *sql.DB, customer, status string) (*sql.Rows, error) {
	query := "SELECT id, total FROM orders " +
~>		"WHERE customer = '" + customer + "' " +
		"AND deleted_at IS NULL"
	if status != "" {
~>		query += " AND status = '" + status + "'"
	}
	return db.QueryContext(ctx, query)
}
