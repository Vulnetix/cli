package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func harden() int {
	syscall.Umask(0o077)
	old := unix.Umask(0)
	unix.Umask(old)
	return old
}
