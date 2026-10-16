package store

import "log"

func Trace(userID string) {
	// bad: "SELECT * FROM users WHERE id = " + userID
	log.Println("loading user " + userID)
	msg := "selected row for " + userID
	_ = msg
}
