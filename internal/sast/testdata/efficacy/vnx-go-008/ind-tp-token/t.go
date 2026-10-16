package auth

import "math/rand"

const letters = "abcdefghijklmnopqrstuvwxyz0123456789"

func NewSessionToken() string {
	b := make([]byte, 32)
	for i := range b {
~>		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
