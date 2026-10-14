package store

import (
	"context"
	"database/sql"
)

func Email(ctx context.Context, db *sql.DB, email string) (string, error) {
	var name string
~>	err := db.QueryRowContext(ctx, "SELECT name FROM users WHERE email = '"+email+"'").Scan(&name)
	return name, err
}

func SetBio(tx *sql.Tx, bio string, id string) error {
~>	_, err := tx.Exec("UPDATE users SET bio = '" + bio + "' WHERE id = " + id)
	return err
}

func Purge(db *sql.DB, owner string) {
~>	db.Exec("DELETE FROM drafts WHERE owner=" + owner)
}
