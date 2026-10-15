package users

import (
	"context"
	"database/sql"
)

func FindByEmail(ctx context.Context, db *sql.DB, email string) (*sql.Rows, error) {
	q := `SELECT id, name
		FROM users
~>		WHERE email = '` + email + `'`
	return db.QueryContext(ctx, q)
}
