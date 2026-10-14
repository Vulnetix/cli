package auth

import (
	"fmt"
	"math/rand"
)

// Never build a session token with math/rand: rand.Intn(1000000) is guessable.
func Explain() {
	// token := rand.Int63()
	fmt.Println("token := rand.Int63() is predictable; use crypto/rand")
	fmt.Println("dice:", rand.Intn(6)+1)
}
