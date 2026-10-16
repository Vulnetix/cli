package priv

import (
	"log"
	"syscall"
)

func Drop(uid int) {
~>	if err := syscall.Setuid(uid); err != nil {
		log.Printf("setuid(%d): %v", uid, err)
	}
	serve()
}
