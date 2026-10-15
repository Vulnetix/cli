package auth

import (
	"fmt"
	"math/rand"
)

func NewSessionID() string {
~>	return fmt.Sprintf("%x", rand.Int63())
}

func SendReset(email string) {
~>	resetCode := rand.Intn(1000000)
	mail(email, fmt.Sprintf("%06d", resetCode))
}
