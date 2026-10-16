package repo

import (
	"database/sql"
	"fmt"
)

func Find(db *sql.DB, name string) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name)
~>	return db.Query(q)
}
