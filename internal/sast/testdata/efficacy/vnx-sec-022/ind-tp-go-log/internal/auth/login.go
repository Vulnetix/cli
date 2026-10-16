package auth

import "log"

func Login(user, password string) {
~>	log.Printf("login attempt user=%s password=%s", user, password)
}
