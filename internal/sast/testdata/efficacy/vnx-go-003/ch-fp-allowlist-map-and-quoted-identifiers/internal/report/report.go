package report

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/lib/pq"
)

var sortable = map[string]string{
	"newest": "created_at DESC",
	"name":   "name ASC",
}

func Items(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	col, ok := sortable[r.URL.Query().Get("sort")]
	if !ok {
		col = "created_at DESC"
	}
	rows, err := db.Query("SELECT id, name FROM items WHERE owner = $1 ORDER BY "+col, r.Context().Value("uid"))
	if err != nil {
		return
	}
	defer rows.Close()
}

func Truncate(db *sql.DB, schema, table string) error {
	_, err := db.Exec(fmt.Sprintf("TRUNCATE %s.%s", pq.QuoteIdentifier(schema), pq.QuoteIdentifier(table)))
	return err
}

func CountRows(db *sql.DB, table string) (int, error) {
	var n int
	q := fmt.Sprintf("SELECT count(*) FROM %s", pgx.Identifier{"public", table}.Sanitize())
	err := db.QueryRow(q).Scan(&n)
	return n, err
}
