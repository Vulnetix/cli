package store

import "database/sql"

func Open() (*sql.DB, error) {
~>	return sql.Open("mysql", "root:root@tcp(mysql:3306)/inventory")
}
