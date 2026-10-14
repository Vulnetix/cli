package drop

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func To(uid, gid int) error {
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	err := syscall.Setuid(uid)
	if err != nil {
		return err
	}
	return unix.Setgroups(nil)
}
