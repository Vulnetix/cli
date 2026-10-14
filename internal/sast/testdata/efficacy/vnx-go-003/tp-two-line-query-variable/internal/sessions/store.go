package sessions

import (
	"context"
	"database/sql"
	"fmt"
)

func Lookup(db *sql.DB, token string) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT user_id, expires FROM sessions WHERE token = '%s'", token)
~>	return db.Query(q)
}

func Revoke(ctx context.Context, tx *sql.Tx, token string) error {
	stmt := "DELETE FROM sessions WHERE token = '" + token + "'"
~>	_, err := tx.ExecContext(ctx, stmt)
	return err
}

// The query starts constant and grows a clause per filter.
func List(db *sql.DB, owner, status string) (*sql.Rows, error) {
	query := "SELECT id, owner, status FROM sessions WHERE 1=1"
	if owner != "" {
		query += " AND owner = '" + owner + "'"
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = '%s'", status)
	}
~>	return db.Query(query)
}
