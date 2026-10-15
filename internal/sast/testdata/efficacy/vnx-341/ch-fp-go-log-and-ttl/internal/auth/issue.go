package auth

import (
	"log"
	"time"
)

func record(token string) time.Time {
	log.Printf("token issued at %v", time.Now())
	tokenExpiry := time.Now().Add(15 * time.Minute)
	return tokenExpiry
}
