package profile

import (
	"database/sql"
	"fmt"
)

type Profile struct {
	ID   int
	Name string
	City string
}

// Load interpolates the caller's id into a multi-line raw-string query. The
// verb sits three lines below fmt.Sprintf.
func (p *Profile) Load(db *sql.DB, uid string) error {
~>	stmt := fmt.Sprintf(`SELECT p.user_id, p.full_name, p.city
		FROM profiles AS p, users AS u
		WHERE p.user_id = u.id
		AND u.id = %s`, uid)
	rows, err := db.Query(stmt)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&p.ID, &p.Name, &p.City); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Rename uses a double-quoted literal split with + across two lines.
func Rename(db *sql.DB, id int, name string) error {
~>	q := fmt.Sprintf("UPDATE profiles "+
		"SET full_name = '%s' WHERE user_id = %d", name, id)
	_, err := db.Exec(q)
	return err
}
