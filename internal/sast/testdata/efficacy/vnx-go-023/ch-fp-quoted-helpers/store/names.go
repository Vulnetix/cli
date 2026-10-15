package store

import (
	"database/sql"

	"github.com/lib/pq"
)

func ByName(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM people WHERE name = " + pq.QuoteLiteral(name))
}

func FromTable(db *sql.DB, table string, owner string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM "+pq.QuoteIdentifier(table)+" WHERE owner = $1", owner)
}
