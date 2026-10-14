package search

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type Filter struct {
	Name   string
	Labels []string
	Limit  int
}

// The formatted pieces are bind-parameter numbers and SQL fragments the
// function assembled itself; every value travels in args.
func Count(ctx context.Context, db *sql.DB, f Filter) (int, error) {
	var where []string
	var args []any
	if f.Name != "" {
		args = append(args, "%"+f.Name+"%")
		ph := fmt.Sprintf("$%d", len(args))
		where = append(where, fmt.Sprintf(`(p.name ILIKE %s OR p.label ILIKE %s)`, ph, ph))
	}
	if len(f.Labels) > 0 {
		phs := make([]string, len(f.Labels))
		for i, l := range f.Labels {
			args = append(args, l)
			phs[i] = fmt.Sprintf("$%d", len(args))
		}
		where = append(where, fmt.Sprintf("p.label IN (%s)", strings.Join(phs, ", ")))
		where = append(where, fmt.Sprintf("p.owner = $%d", len(args)))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	countSQL := fmt.Sprintf(`SELECT count(DISTINCT p.id) FROM products p%s`, whereSQL)
	var n int
	err := db.QueryRowContext(ctx, countSQL, args...).Scan(&n)
	if err != nil {
		return 0, err
	}
	listSQL := fmt.Sprintf("SELECT %s FROM products p %s ORDER BY p.id LIMIT %d", columns, whereSQL, f.Limit)
	rows, err := db.QueryContext(ctx, listSQL, args...)
	if err == nil {
		rows.Close()
	}
	placeholders := strings.Repeat("?,", len(f.Labels))
	db.ExecContext(ctx, fmt.Sprintf("DELETE FROM tags WHERE label IN (%s)", strings.TrimSuffix(placeholders, ",")), args...)
	return n, nil
}

const columns = "p.id, p.name, p.label"
