package users

import "log"

// Do not hash with md5.Sum([]byte(password)); use bcrypt.
func warn() {
	log.Println("md5.Sum([]byte(password)) is not a password hash")
}
