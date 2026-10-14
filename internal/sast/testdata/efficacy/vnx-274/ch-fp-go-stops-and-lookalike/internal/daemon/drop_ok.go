package daemon

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

func demoteOK(uid, gid int, dir, p string) error {
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	err := unix.Setuid(uid)
	if err != nil {
		log.Fatalf("setuid: %v", err)
	}
	if err := unix.Chroot(dir); err != nil {
		panic(err)
	}
	if err := os.Chown(p, uid, gid); err != nil {
		log.Printf("chown: %v", err)
	}
	return nil
}
