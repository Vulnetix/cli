package runner

import (
	"os"
	"os/exec"
	"syscall"
)

func RunInRootfs(rootfs string, argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
~>		Chroot:  rootfs,
		Setpgid: true,
	}
	return cmd.Run()
}
