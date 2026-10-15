package store

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func Open() (*sql.DB, error) {
~>	return sql.Open("mysql", "app:Wr7tY2kPq9@tcp(@@sample:d[b][.]p[r]od[.]ac[m]e[.][n]et@@:3306)/app?parseTime=true")
}
