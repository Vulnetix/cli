package svc

import (
	"errors"
	"log"
)

var ErrInvalidToken = errors.New("invalid token")

func report(email, nextPageToken string, tokenCount int, passwordPolicy, secretName, keyID string, password string) {
	log.Printf("password reset requested for %s", email)
	log.Printf("page %s, %d tokens", nextPageToken, tokenCount)
	log.Printf("policy=%s secret=%s key=%s", passwordPolicy, secretName, keyID)
	log.Printf("password length %d", len(password))
	log.Printf("failed: %v", ErrInvalidToken)
}
