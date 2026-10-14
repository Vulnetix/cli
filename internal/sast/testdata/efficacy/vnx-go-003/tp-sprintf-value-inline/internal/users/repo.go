package users

import (
	"context"
	"database/sql"
	"fmt"
)

type User struct {
	ID    int64
	Email string
}

func FindByName(db *sql.DB, name string) (*User, error) {
	var u User
~>	row := db.QueryRow(fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name))
	return &u, row.Scan(&u.ID, &u.Email)
}

func Deactivate(db *sql.DB, id string) error {
~>	_, err := db.Exec(fmt.Sprintf("UPDATE users SET active = false WHERE id = %s", id))
	return err
}

func Search(ctx context.Context, db *sql.DB, term string) (*sql.Rows, error) {
~>	return db.QueryContext(ctx, fmt.Sprintf("SELECT id FROM users WHERE email LIKE '%%%s%%'", term))
}

func Audit(ctx context.Context, db *sql.DB, actor string) (*sql.Rows, error) {
~>	rows, err := db.QueryContext(
		ctx,
		fmt.Sprintf("SELECT id, action FROM audit WHERE actor = '%s'", actor),
	)
	return rows, err
}
