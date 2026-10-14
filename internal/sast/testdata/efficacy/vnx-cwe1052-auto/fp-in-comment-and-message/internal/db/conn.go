package db

import (
	"database/sql"
	"log/slog"
)

// Open connects to the database named in dsn, for example
// "postgres://app@10.0.4.12:5432/orders" in production.
func Open(dsn string) (*sql.DB, error) {
	slog.Info("connecting to postgres://app@10.0.4.12:5432/orders is no longer the default")
	// return sql.Open("postgres", "host=10.0.4.12 port=5432")
	return sql.Open("postgres", dsn)
}
