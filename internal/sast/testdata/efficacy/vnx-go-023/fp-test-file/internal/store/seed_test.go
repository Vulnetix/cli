package store

import "testing"

func TestSeed(t *testing.T) {
	db := openTestDB(t)
	for _, name := range []string{"alice", "bob"} {
		if _, err := db.Exec("INSERT INTO users (name) VALUES ('" + name + "')"); err != nil {
			t.Fatal(err)
		}
	}
}
