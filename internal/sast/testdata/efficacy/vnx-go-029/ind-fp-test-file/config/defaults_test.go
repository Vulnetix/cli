package config

import "testing"

func TestDevDB(t *testing.T) {
	password := "admin"
	db := DB{User: "sa", Password: "changeme"}
	if db.Password == password {
		t.Fatal("same")
	}
}
