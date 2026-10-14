package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func main() {
~>	syscall.Umask(0)
	if err := os.MkdirAll("/var/spool/agent", 0777); err != nil {
		panic(err)
	}
	run()
}

func prepareSockets() {
~>	unix.Umask(0o000)
	listen("/run/agent.sock")
}
