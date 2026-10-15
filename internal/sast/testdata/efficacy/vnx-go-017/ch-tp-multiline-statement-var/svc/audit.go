package svc

import (
	"database/sql"
	"fmt"
)

func RecordLogin(db *sql.DB, user, ip string) error {
~>	stmt := fmt.Sprintf(
		"INSERT INTO audit (username, ip) VALUES ('%s', '%s')",
		user, ip,
	)
	_, err := db.Exec(stmt)
	return err
}
