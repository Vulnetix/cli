package auth

import "log"

func Check(user string, password string) {
	log.Printf("login attempt for %s (password length %d)", user, len(password))
	log.Printf("password_reset requested for %s", user)
	log.Println("missing token")
}
