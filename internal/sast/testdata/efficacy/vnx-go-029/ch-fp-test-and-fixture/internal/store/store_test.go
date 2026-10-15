package store

import "testing"

func TestOpen(t *testing.T) {
	cfg := Config{User: "root", Password: "root"}
	if _, err := Open(cfg, "root:root@tcp(127.0.0.1:3306)/test"); err != nil {
		t.Fatal(err)
	}
}
