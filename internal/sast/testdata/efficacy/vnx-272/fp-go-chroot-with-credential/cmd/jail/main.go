package main

import (
	"os/exec"
	"syscall"
)

func runJailed(root string, uid, gid uint32) error {
	cmd := exec.Command("/bin/worker")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:     root,
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}
	return cmd.Run()
}
