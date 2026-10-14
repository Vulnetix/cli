package store

import (
	"context"
	"database/sql"

	"google.golang.org/grpc"
)

func Open() (*sql.DB, error) {
~>	return sql.Open("postgres", "host=db-primary.acme-corp.net port=5432 user=app dbname=orders sslmode=require")
}

func OpenMySQL() (*sql.DB, error) {
~>	return sql.Open("mysql", "mysql://app@172.31.4.18:3306/orders?parseTime=true")
}

func Ledger(ctx context.Context) (*grpc.ClientConn, error) {
~>	return grpc.DialContext(ctx, "10.0.12.4:50051", grpc.WithBlock())
}
