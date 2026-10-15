package jail

import (
	"os"
	"syscall"
)

func Enter(root string) error {
	if err := syscall.Chroot(root); err != nil {
		return err
	}
	return os.Chdir("/")
}
