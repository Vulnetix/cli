package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

func CountRows(db *sql.DB, table string, owner string) (int, error) {
	q := fmt.Sprintf("SELECT count(*) FROM %s WHERE owner = $1", pq.QuoteIdentifier(table))
	var n int
	err := db.QueryRow(q, owner).Scan(&n)
	return n, err
}

func Lookup(db *sql.DB, name string) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT * FROM people WHERE name = %s", pq.QuoteLiteral(name))
	return db.Query(q)
}

func Insert(db *sql.DB, cols []string, vals []any) error {
	ph := make([]string, len(cols))
	for i := range cols {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	q := fmt.Sprintf("INSERT INTO items (%s) VALUES (%s)", strings.Join(cols, ","), strings.Join(ph, ","))
	_, err := db.Exec(q, vals...)
	return err
}
