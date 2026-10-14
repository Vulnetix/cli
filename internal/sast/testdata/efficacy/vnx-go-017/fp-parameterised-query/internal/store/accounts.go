package store

import (
	"context"
	"database/sql"
	"fmt"
)

func ByName(ctx context.Context, db *sql.DB, name string) (*sql.Rows, error) {
	return db.QueryContext(ctx, "SELECT id, email FROM users WHERE name = $1", name)
}

func Disable(db *sql.DB, id string) error {
	_, err := db.Exec("UPDATE accounts SET disabled = true WHERE id = ?", id)
	return err
}

// Only an integer is formatted into the text.
func Page(db *sql.DB, owner string, limit, offset int) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT id FROM accounts WHERE owner = $1 LIMIT %d OFFSET %d", limit, offset)
	return db.Query(q, owner)
}

func wrap(err error, id string) error {
	return fmt.Errorf("select account '%s': %w", id, err)
}
