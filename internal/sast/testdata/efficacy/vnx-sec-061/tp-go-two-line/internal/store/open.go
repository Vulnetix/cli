package store

import "database/sql"

~>const dsn = "postgresql://billing:@@sample:[A-Za-z0-9]{20}@@@10.20.4.11:5432/billing?sslmode=require"

func Open() (*sql.DB, error) { return sql.Open("pgx", dsn) }
