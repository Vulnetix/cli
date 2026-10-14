package store

import (
	"database/sql"
	"fmt"
	"testing"
)

// Seeding a test database from the test's own constants.
func seed(t *testing.T, db *sql.DB) {
	for i, name := range []string{"alice", "bob"} {
		if _, err := db.Exec(fmt.Sprintf("INSERT INTO users (id, name) VALUES (%d, '%s')", i, name)); err != nil {
			t.Fatal(err)
		}
	}
}
