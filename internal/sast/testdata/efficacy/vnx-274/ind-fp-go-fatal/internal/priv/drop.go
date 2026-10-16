package priv

import (
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

func Drop(uid, gid int) error {
	if err := unix.Setgid(gid); err != nil {
		log.Fatalf("setgid: %v", err)
	}
	if err := unix.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	return nil
}
