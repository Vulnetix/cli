package sandbox

import (
	"os"
	"os/exec"
	"syscall"
)

// Run executes argv inside rootfs.
func Run(rootfs string, argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
~>	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: rootfs, Setpgid: true}
	return cmd.Run()
}
