package auth

import (
	"fmt"
	"math/rand"
)

func NewSessionToken() string {
~>	r := rand.New(rand.NewSource(42))
	return fmt.Sprintf("%016x", r.Uint64())
}
