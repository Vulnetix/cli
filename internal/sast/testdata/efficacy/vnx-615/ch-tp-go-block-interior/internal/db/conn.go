package db

/*
   Staging database, reset weekly:
~>   admin_password = Winter2024!
   host = db.staging.internal
*/

import "database/sql"

func Open(dsn string) (*sql.DB, error) {
	return sql.Open("postgres", dsn)
}
