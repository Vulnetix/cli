package store

import "database/sql"

func Purge(db *sql.DB, email string) error {
~>	stmt := "DELETE FROM sessions WHERE email = '" + email + "'"
	_, err := db.Exec(stmt)
	return err
}
