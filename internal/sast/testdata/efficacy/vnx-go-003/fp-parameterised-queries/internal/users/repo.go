package users

import (
	"context"
	"database/sql"

	"gorm.io/gorm"
)

func FindByName(db *sql.DB, name string) *sql.Row {
	return db.QueryRow("SELECT id, email FROM users WHERE name = $1", name)
}

func Search(ctx context.Context, db *sql.DB, term string) (*sql.Rows, error) {
	return db.QueryContext(ctx, "SELECT id FROM users WHERE email LIKE '%' || ? || '%'", term)
}

func ByEmail(g *gorm.DB, email string) error {
	var u struct{ ID int }
	if err := g.Where("email = ?", email).First(&u).Error; err != nil {
		return err
	}
	return g.Raw("SELECT * FROM users WHERE id = ?", u.ID).Scan(&u).Error
}

func Rename(ctx context.Context, tx *sql.Tx, id int64, name string) error {
	const q = "UPDATE users SET name = $1 WHERE id = $2"
	_, err := tx.ExecContext(ctx, q, name, id)
	return err
}
