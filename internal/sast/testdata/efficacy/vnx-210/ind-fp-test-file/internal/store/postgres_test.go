package store

import (
	"fmt"
	"testing"
)

func TestOpenFailsWithBadPassword(t *testing.T) {
	cfg := Config{Host: "localhost", User: "app", Password: "wrong"}
	if _, err := Open(cfg); err == nil {
		t.Fatal(fmt.Errorf("expected failure for password %s", cfg.Password))
	}
}
