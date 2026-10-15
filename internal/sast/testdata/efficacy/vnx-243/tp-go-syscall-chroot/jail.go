package jail

import "syscall"

func Enter(dir string) error {
~>	if err := syscall.Chroot(dir); err != nil {
		return err
	}
	return syscall.Setuid(65534)
}
