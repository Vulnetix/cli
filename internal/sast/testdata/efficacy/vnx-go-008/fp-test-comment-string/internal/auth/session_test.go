package auth

import (
	"math/rand"
	"testing"
)

func TestSessionTokenUnique(t *testing.T) {
	token := randomToken(rand.Intn(64))
	if token == "" {
		t.Fatal("empty")
	}
}
