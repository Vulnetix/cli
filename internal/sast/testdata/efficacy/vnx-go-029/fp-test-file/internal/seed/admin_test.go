package seed

import "testing"

func TestLogin(t *testing.T) {
	password := "admin"
	u := &User{}
	u.SetPassword("password")
	_ = password
}
