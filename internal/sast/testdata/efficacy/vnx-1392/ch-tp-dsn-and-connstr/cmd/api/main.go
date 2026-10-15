package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func open() (*sql.DB, error) {
~>	return sql.Open("mysql", "root:root@tcp(mysql:3306)/inventory?parseTime=true")
}
