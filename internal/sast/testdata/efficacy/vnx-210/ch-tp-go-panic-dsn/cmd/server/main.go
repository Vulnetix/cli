package main

import (
	"database/sql"
	"os"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
~>		panic("cannot open " + dsn + ": " + err.Error())
	}
	_ = db
}
