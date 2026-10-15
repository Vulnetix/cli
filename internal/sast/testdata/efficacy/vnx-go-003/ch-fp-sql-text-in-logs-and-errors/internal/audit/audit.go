package audit

import (
	"database/sql"
	"fmt"
	"log"
)

const insertEvent = "INSERT INTO audit_events (actor, action) VALUES ($1, $2)"

func Record(db *sql.DB, actor, action string) error {
	if _, err := db.Exec(insertEvent, actor, action); err != nil {
		log.Printf("audit insert failed: INSERT INTO audit_events VALUES ('%s', '%s'): %v", actor, action, err)
		return fmt.Errorf("record %s for user = '%s': %w", action, actor, err)
	}
	return nil
}

// Example of what not to do, kept for the onboarding notes:
//   db.Exec("DELETE FROM audit_events WHERE actor = '" + actor + "'")
func Purge(db *sql.DB, actor string) error {
	_, err := db.Exec("DELETE FROM audit_events WHERE actor = $1", actor)
	return err
}
