package store

import "database/sql"

type User struct{ ID, Name string }

func Get(db *sql.DB, userID string) (u User, err error) {
~>	query := "SELECT id, name FROM users WHERE id = " + userID
	err = db.QueryRow(query).Scan(&u.ID, &u.Name)
	return
}
