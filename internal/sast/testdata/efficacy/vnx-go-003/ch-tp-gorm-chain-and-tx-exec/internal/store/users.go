package store

import (
	"context"
	"database/sql"
	"fmt"

	"gorm.io/gorm"
)

type User struct {
	ID    uint
	Email string
}

type Store struct{ db *gorm.DB }

func (s *Store) ByEmail(ctx context.Context, email string) (*User, error) {
	var u User
~>	err := s.db.WithContext(ctx).Where(fmt.Sprintf("email = '%s'", email)).First(&u).Error
	return &u, err
}

func Revoke(tx *sql.Tx, tok string) error {
~>	_, err := tx.Exec("DELETE FROM sessions WHERE token = '" + tok + "'")
	return err
}

func Rename(ctx context.Context, conn *sql.Conn, id int, name string) error {
	sqlStr := fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %d", name, id)
~>	_, err := conn.ExecContext(ctx, sqlStr)
	return err
}
