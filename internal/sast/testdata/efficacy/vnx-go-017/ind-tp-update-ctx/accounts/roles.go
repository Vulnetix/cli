package accounts

import (
	"context"
	"database/sql"
	"fmt"
)

func SetRole(ctx context.Context, db *sql.DB, id int, role string) error {
~>	stmt := fmt.Sprintf("UPDATE accounts SET role = '%s' WHERE id = %d", role, id)
	_, err := db.ExecContext(ctx, stmt)
	return err
}
