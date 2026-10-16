package repo

import (
	"context"
	"database/sql"
)

func Delete(ctx context.Context, db *sql.DB, id string) error {
~>	_, err := db.ExecContext(ctx, "DELETE FROM orders WHERE id = "+id)
	return err
}
