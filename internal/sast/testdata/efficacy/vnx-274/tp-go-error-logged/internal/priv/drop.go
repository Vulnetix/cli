package priv

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func Drop(uid, gid int) {
	err := unix.Setgid(gid)
~>	if err != nil {
		fmt.Fprintln(os.Stderr, "setgid:", err)
	}
~>	if err := syscall.Setuid(uid); err != nil {
		log.Printf("setuid: %v", err)
	}
	serve()
}
