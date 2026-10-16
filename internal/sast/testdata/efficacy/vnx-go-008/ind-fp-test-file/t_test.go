package auth

import (
	"math/rand"
	"testing"
)

func TestToken(t *testing.T) {
	token := rand.Intn(1000)
	_ = token
}
