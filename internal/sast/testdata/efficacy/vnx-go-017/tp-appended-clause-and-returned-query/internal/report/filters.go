package report

import (
	"database/sql"
	"fmt"
)

// The clause has no statement keyword of its own, but the variable it is
// appended to is run as a query a few lines later.
func Overdue(db *sql.DB, status string, region string) (*sql.Rows, error) {
	query := "SELECT id FROM invoices WHERE due < now()"
	if status != "" {
~>		query += fmt.Sprintf(" AND status = '%s'", status)
	}
	if region != "" {
~>		query = query + fmt.Sprintf(" AND region='%s'", region)
	}
	return db.Query(query)
}

// A builder that hands the formatted statement back to its caller.
func userByEmail(email string) string {
~>	return fmt.Sprintf("SELECT id, name FROM users WHERE email = '%s'", email)
}
