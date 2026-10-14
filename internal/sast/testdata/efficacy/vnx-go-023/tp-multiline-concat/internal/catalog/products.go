package catalog

import "database/sql"

// The statement is split across lines; the value is concatenated on the
// second one.
func ByCategory(db *sql.DB, category string, maxPrice string) (*sql.Rows, error) {
	q := "SELECT id, name, price FROM products " +
~>		"WHERE category = '" + category + "' " +
~>		"AND price < " + maxPrice
	return db.Query(q)
}

func ByVendor(db *sql.DB, vendor string) (*sql.Rows, error) {
	return db.Query(
~>		"SELECT id FROM products WHERE vendor = '" +
			vendor + "'",
	)
}
