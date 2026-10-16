package store

import "database/sql"

func Open() (*sql.DB, error) {
~>	return sql.Open("mysql", "orders:Xk9Pq4Lm7Tz@tcp(10.0.4.12:3306)/orders")
}
