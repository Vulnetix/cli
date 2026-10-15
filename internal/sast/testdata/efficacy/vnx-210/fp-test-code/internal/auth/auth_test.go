package auth

import (
	"fmt"
	"testing"
)

func TestLogin(t *testing.T) {
	password := "hunter2-test-only"
	if err := login("u", password); err == nil {
		panic(fmt.Errorf("login accepted %s", password))
	}
}
