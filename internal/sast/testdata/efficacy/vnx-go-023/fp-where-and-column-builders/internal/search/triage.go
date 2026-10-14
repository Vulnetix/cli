package search

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

const suppressionCols = `"id", "orgId", "rule", "expiresAt"`

// Every concatenated piece is a fragment the function built itself (a WHERE
// clause of placeholders, a constant column list, a FROM clause); every value
// is a bind parameter in args.
func Find(ctx context.Context, db *sql.DB, org string, kinds []string) error {
	var where []string
	args := []any{org}
	where = append(where, `d."orgId" = $1`)
	for _, k := range kinds {
		args = append(args, k)
		where = append(where, `d.kind = $`+strconv.Itoa(len(args)))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	from := `"Defence" d JOIN "Advisory" a ON a.id = d."advisoryId"`
	countSQL := `SELECT count(*) FROM "Defence" d` + whereSQL
	var n int
	if err := db.QueryRowContext(ctx, countSQL, args...).Scan(&n); err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, `SELECT d.kind, COUNT(*) FROM `+from+` WHERE `+strings.Join(where, " AND ")+` GROUP BY d.kind`, args...)
	if err != nil {
		return err
	}
	rows.Close()
	q := `SELECT ` + suppressionCols + ` FROM "Suppression" WHERE "orgId" = $1`
	_, err = db.QueryContext(ctx, q, org)
	if err != nil {
		return err
	}
	// A subquery builder handed only its placeholder numbers.
	return db.QueryRowContext(ctx,
		`SELECT "id" FROM "Provider" WHERE "id" = `+visibleProviderSQL("$1", "$2"), org, kinds[0],
	).Scan(&n)
}

func visibleProviderSQL(slugArg, orgArg string) string {
	return `(SELECT p."id" FROM "Provider" p WHERE p.slug = ` + slugArg + ` AND p."orgId" = ` + orgArg + `)`
}
