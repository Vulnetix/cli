package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
)

var sortColumns = map[string]string{
	"name":  "name",
	"email": "email",
}

func List(ctx context.Context, db *sql.DB, r *http.Request) (*sql.Rows, error) {
	col, ok := sortColumns[r.URL.Query().Get("sort")]
	if !ok {
		col = "id"
	}
	return db.QueryContext(ctx, fmt.Sprintf("SELECT id, name FROM users ORDER BY %s", col))
}
