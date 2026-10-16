package repo

import (
	"database/sql"
	"fmt"
)

func ByID(db *sql.DB, id int) (*sql.Rows, error) {
	return db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}
