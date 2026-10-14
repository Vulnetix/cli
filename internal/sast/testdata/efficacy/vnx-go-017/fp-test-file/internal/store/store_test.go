package store

import (
	"fmt"
	"testing"
)

// Fixture setup in a test formats known values; it is not the attack surface.
func TestSeed(t *testing.T) {
	db := openTestDB(t)
	for _, name := range []string{"alice", "bob"} {
		if _, err := db.Exec(fmt.Sprintf("INSERT INTO users (name) VALUES ('%s')", name)); err != nil {
			t.Fatal(err)
		}
	}
}
