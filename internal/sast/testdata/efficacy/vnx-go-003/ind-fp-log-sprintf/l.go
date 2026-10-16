package repo

import (
	"fmt"
	"log"
)

func Note(name string) {
	msg := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	log.Println("would run:", msg)
}
