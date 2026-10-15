package svc

import (
	"database/sql"
	"fmt"
)

// Never do this: db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
func Safe(db *sql.DB, name string) (*sql.Rows, error) {
	// q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	hint := "use db.Query(fmt.Sprintf(\"... '%s'\")) never"
	_ = hint
	return db.Query("SELECT * FROM users WHERE name = $1", name)
}
