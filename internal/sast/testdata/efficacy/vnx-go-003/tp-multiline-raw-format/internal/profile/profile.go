package profile

import (
	"database/sql"
	"fmt"
)

type Profile struct {
	UserID int
	Name   string
	City   string
}

func Load(db *sql.DB, uid string) (*Profile, error) {
	query := fmt.Sprintf(`
		SELECT p.user_id, p.full_name, p.city
		FROM profiles AS p
		JOIN users AS u ON p.user_id = u.id
		WHERE u.id = %s`, uid)
~>	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var p Profile
	for rows.Next() {
		if err := rows.Scan(&p.UserID, &p.Name, &p.City); err != nil {
			return nil, err
		}
	}
	return &p, nil
}
