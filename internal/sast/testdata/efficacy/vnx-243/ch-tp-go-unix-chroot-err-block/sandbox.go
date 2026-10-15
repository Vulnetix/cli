package sandbox

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func Enter(root string, argv []string) error {
~>	if err := unix.Chroot(root); err != nil {
		return err
	}
	return syscall.Exec(argv[0], argv, nil)
}
