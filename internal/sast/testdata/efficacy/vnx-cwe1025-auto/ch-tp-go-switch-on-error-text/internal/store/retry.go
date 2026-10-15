package store

import "database/sql"

func classify(err error) string {
~>	switch err.Error() {
	case "sql: no rows in result set":
		return "missing"
	}
	return "other"
}

func isMissing(row *sql.Row) bool {
	var id int
	err := row.Scan(&id)
	if err != nil {
		text := err.Error()
~>		if text == "sql: no rows in result set" {
			return true
		}
	}
	return false
}
