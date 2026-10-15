package store

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func Open() (*sql.DB, error) {
~>	return sql.Open("mysql", "shop@tcp(10.0.4.21:3306)/shop?parseTime=true")
}

func OpenReplica() (*sql.DB, error) {
~>	dsn := "reader@tcp(mysql-replica.prod.acme-corp.net:3306)/shop"
	return sql.Open("mysql", dsn)
}
