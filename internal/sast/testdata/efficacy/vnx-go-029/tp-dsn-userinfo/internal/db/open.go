package db

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
)

func Open() (*sql.DB, error) {
~>	return sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/shop")
}

func Connect(ctx context.Context) (*pgx.Conn, error) {
~>	return pgx.Connect(ctx, "postgres://postgres:postgres@db:5432/app?sslmode=disable")
}
