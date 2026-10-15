package db

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

func Configure(ctx context.Context, conn *sql.Conn, timeoutMs, workMemMB int) error {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET statement_timeout = %d", timeoutMs)); err != nil {
		return err
	}
	_, err := conn.ExecContext(ctx, fmt.Sprintf("SET work_mem = '%dMB'", workMemMB))
	return err
}

func Recent(db *sql.DB, limit int) (*sql.Rows, error) {
	return db.Query("SELECT id, title FROM posts ORDER BY created_at DESC LIMIT " + strconv.Itoa(limit))
}

func Page(db *sql.DB, owner string, page int) (*sql.Rows, error) {
	return db.Query(fmt.Sprintf("SELECT id FROM posts WHERE owner = $1 LIMIT 20 OFFSET %d", page*20), owner)
}
