package store

import (
	"database/sql"
	"fmt"
)

const auditTable = "audit_log"

func Count(db *sql.DB) (n int, err error) {
	err = db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", auditTable)).Scan(&n)
	return
}
