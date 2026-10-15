package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Accounts struct{ pool *pgxpool.Pool }

func (a *Accounts) ByEmail(ctx context.Context, email string) (int64, error) {
	var id int64
~>	err := a.pool.QueryRow(ctx, fmt.Sprintf("SELECT id FROM accounts WHERE email = '%s'", email)).Scan(&id)
	return id, err
}

func (a *Accounts) Rename(ctx context.Context, id int64, display string) error {
	_, err := a.pool.Exec(ctx,
~>		fmt.Sprintf("UPDATE accounts SET display_name='%v' WHERE id=%d", display, id))
	return err
}
