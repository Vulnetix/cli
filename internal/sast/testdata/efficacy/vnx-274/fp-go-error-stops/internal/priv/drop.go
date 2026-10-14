package priv

import (
	"fmt"
	"log"
	"syscall"

	"golang.org/x/sys/unix"
)

func Drop(uid, gid int) error {
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	err := syscall.Setuid(uid)
	if err != nil {
		log.Fatalf("setuid: %v", err)
	}
	if err := syscall.Setgroups(nil); err != nil {
		panic(err)
	}
	return nil
}
