package main

import (
	"log"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	root := os.Args[1]
~>	if err := syscall.Chroot(root); err != nil {
		log.Fatal(err)
	}
	if err := syscall.Chdir("/"); err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command("/bin/worker")
	cmd.SysProcAttr = &syscall.SysProcAttr{
~>		Chroot: root,
	}
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
