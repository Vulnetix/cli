package web

import (
	"database/sql"
	"fmt"
	"log"
)

func Report(db *sql.DB, user string) {
	// fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user) is what we never do
	msg := fmt.Sprintf("user %s selected an item from the menu", user)
	log.Println(msg)
	rows, err := db.Query("SELECT id FROM menu WHERE owner = ?", user)
	if err != nil {
		log.Println(fmt.Sprintf("query failed: %v", err))
		return
	}
	defer rows.Close()
}
