package store

import "database/sql"

func Open() (*sql.DB, error) {
~>	return sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/shop")
}
