package repo

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

func Page(db *sqlx.DB, limit string) error {
	var out []string
~>	return db.Select(&out, fmt.Sprintf("SELECT name FROM t ORDER BY id LIMIT %s", limit))
}
