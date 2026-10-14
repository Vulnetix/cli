package auth

import (
	"errors"
	"log"
)

var ErrInvalidToken = errors.New("invalid token")

func reset(email string, err error) {
	log.Printf("password reset requested for %s", email)
	log.Printf("token expired: %v", err)
	log.Println("secret store unavailable, retrying")
	log.Printf("auth failed: %v", ErrInvalidToken)
	// log.Printf("password=%s", password)
}
