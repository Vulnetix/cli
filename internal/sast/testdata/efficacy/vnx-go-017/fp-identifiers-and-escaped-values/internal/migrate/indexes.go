package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/lib/pq"
)

var trigramIndexes = []struct{ name, table, column string }{
	{"idx_products_name_trgm", "products", "name"},
	{"idx_vendors_name_trgm", "vendors", "name"},
}

// Identifiers cannot be bound, so DDL over a fixed list of names is formatted;
// none of these names come from outside the program.
func Rebuild(ctx context.Context, db *sql.DB) error {
	for _, idx := range trigramIndexes {
		if _, err := db.ExecContext(ctx, fmt.Sprintf(`DROP INDEX CONCURRENTLY IF EXISTS "%s"`, idx.name)); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX CONCURRENTLY "%s" ON "%s" USING gin ("%s" gin_trgm_ops)`, idx.name, idx.table, idx.column)); err != nil {
			return err
		}
	}
	return nil
}

// Values that were quoted for SQL or are digits by construction.
func Tag(ctx context.Context, db *sql.DB, name string, id int) error {
	q := fmt.Sprintf("UPDATE tags SET name = %s WHERE id = '%s'", pq.QuoteLiteral(name), strconv.Itoa(id))
	_, err := db.ExecContext(ctx, q)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf("ANALYZE %s", pq.QuoteIdentifier("tags")))
	return err
}

func Truncate(ctx context.Context, db *sql.DB, table string) error {
	_, err := db.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s", pq.QuoteIdentifier(table)))
	return err
}
