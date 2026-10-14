package runner

import (
	"os/exec"
	"syscall"
)

// Start runs argv jailed in root as uid:gid.
func Start(root string, uid, gid uint32, argv []string) (*exec.Cmd, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
	return cmd, cmd.Start()
}
