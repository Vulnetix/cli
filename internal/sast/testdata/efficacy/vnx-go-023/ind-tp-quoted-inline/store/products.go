package store

import (
	"context"
	"database/sql"
)

func ByCategory(ctx context.Context, db *sql.DB, category string) (*sql.Rows, error) {
~>	return db.QueryContext(ctx, "SELECT * FROM products WHERE category = '"+category+"'")
}
