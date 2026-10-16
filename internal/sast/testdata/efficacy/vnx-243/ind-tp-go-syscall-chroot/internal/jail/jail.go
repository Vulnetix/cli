package jail

import (
	"fmt"
	"syscall"
)

func Enter(dir string) error {
~>	if err := syscall.Chroot(dir); err != nil {
		return fmt.Errorf("chroot %s: %w", dir, err)
	}
	return syscall.Setuid(65534)
}
