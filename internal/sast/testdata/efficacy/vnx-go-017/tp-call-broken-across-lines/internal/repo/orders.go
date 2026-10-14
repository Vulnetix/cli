package repo

import (
	"context"
	"database/sql"
	"fmt"
)

type Repo struct {
	db *sql.DB
}

func (r *Repo) ByCustomer(ctx context.Context, customer string) (*sql.Rows, error) {
	return r.db.QueryContext(
		ctx,
~>		fmt.Sprintf("SELECT id, total FROM orders WHERE customer = '%s'", customer),
	)
}

func (r *Repo) Count(ctx context.Context, status string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
~>		fmt.Sprintf(
			"SELECT count(*) FROM orders WHERE status = '%s'", status)).Scan(&n)
	return n, err
}
