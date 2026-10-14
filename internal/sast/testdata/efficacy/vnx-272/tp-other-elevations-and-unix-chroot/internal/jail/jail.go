package jail

import "golang.org/x/sys/unix"

func Enter(root string) error {
~>	if err := unix.Chroot(root); err != nil {
		return err
	}
	return unix.Chdir("/")
}
