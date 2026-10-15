package main

import "database/sql"

const (
	defaultAdminUser = "admin"
~>	defaultAdminPass = "admin"
)

type Settings struct {
	DBUser string
	DBPass string
}

var settings = Settings{
	DBUser: "sa",
~>	DBPass: "Passw0rd",
}

func open() (*sql.DB, error) {
~>	return sql.Open("sqlserver", "sqlserver://sa:password@localhost:1433?database=app")
}
