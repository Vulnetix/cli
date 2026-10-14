package profile

import (
	"database/sql"
	"fmt"
	"log"
)

func describe(uid string) string {
	query := fmt.Sprintf("SELECT * FROM profiles WHERE id = '%s'", uid)
	log.Println("would run", query)
	return query
}

// The same name in another function is a different variable.
func Load(db *sql.DB, uid string) (*sql.Rows, error) {
	const query = `SELECT user_id, full_name FROM profiles WHERE user_id = ?`
	return db.Query(query, uid)
}

// A later plain assignment replaces what the variable held.
func LoadByEmail(db *sql.DB, email string) (*sql.Rows, error) {
	q := fmt.Sprintf("SELECT * FROM profiles WHERE email = '%s'", email)
	log.Println("legacy form was", q)
	q = "SELECT * FROM profiles WHERE email = $1"
	return db.Query(q, email)
}
