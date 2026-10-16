package svc

import "log"

func attempt(user, password string) {
~>	log.Printf("login attempt user=%s password=%s", user, password)
}
