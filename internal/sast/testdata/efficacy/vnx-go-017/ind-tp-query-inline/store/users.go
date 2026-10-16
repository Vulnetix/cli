package store

import (
	"database/sql"
	"fmt"
)

type UserStore struct{ db *sql.DB }

func (s *UserStore) FindByName(username string) (*sql.Rows, error) {
~>	return s.db.Query(fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", username))
}
