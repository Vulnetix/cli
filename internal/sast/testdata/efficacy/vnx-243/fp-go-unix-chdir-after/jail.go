package jail

import (
	"os"

	"golang.org/x/sys/unix"
)

func Enter(dir string) error {
	if err := unix.Chroot(dir); err != nil {
		return err
	}
	return os.Chdir("/")
}
