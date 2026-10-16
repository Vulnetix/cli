package store

import (
	"context"
	"database/sql"
	"fmt"
)

func Find(ctx context.Context, db *sql.DB, name string, age int) (*sql.Rows, error) {
	log := fmt.Sprintf("looking up %s aged %d", name, age)
	_ = log
	return db.QueryContext(ctx, "SELECT id, email FROM users WHERE name = $1 AND age = $2", name, age)
}

func ByID(db *sql.DB, id int) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT email FROM users WHERE id = %d", id))
}
