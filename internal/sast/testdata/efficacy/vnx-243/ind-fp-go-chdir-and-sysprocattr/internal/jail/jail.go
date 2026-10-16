package jail

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func Enter(dir string) error {
	if err := unix.Chroot(dir); err != nil {
		return err
	}
	return os.Chdir("/")
}

func Spawn(dir string) *exec.Cmd {
	cmd := exec.Command("/bin/worker")
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: dir}
	return cmd
}
