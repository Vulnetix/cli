package search

import (
	"context"
	"database/sql"
	"fmt"
)

type Repo struct{ db *sql.DB }

func (r *Repo) Find(ctx context.Context, term string) (*sql.Rows, error) {
~>	return r.db.QueryContext(ctx, fmt.Sprintf("SELECT id, name FROM customers WHERE name ILIKE '%%%[1]s%%' OR email ILIKE '%%%[1]s%%'", term))
}
