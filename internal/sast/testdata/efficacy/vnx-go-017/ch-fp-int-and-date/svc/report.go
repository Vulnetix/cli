package svc

import (
	"database/sql"
	"fmt"
)

func Recent(db *sql.DB, days int, limit int) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT * FROM events WHERE age_days < %d LIMIT %d", days, limit)
	return db.Query(q)
}

const tableName = "events"

func Purge(db *sql.DB, before string) error {
	_, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE created < $1", tableName), before)
	return err
}
