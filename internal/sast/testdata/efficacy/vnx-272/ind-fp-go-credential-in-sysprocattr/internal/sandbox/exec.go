package sandbox

import (
	"os/exec"
	"syscall"
)

func Spawn(rootfs string, uid, gid uint32, argv []string) *exec.Cmd {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:     rootfs,
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}
	return cmd
}
