package auth

import (
	"math/rand"
	"time"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func init() {
~>	rand.Seed(time.Now().UnixNano())
}

// GenerateAPIToken returns a random API token for a new client.
func GenerateAPIToken(n int) string {
	token := make([]byte, n)
	for i := range token {
		token[i] = letters[rand.Intn(len(letters))]
	}
	return string(token)
}
