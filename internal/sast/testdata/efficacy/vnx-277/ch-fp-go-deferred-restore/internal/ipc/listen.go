package ipc

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func ListenPrivate(path string) (net.Listener, error) {
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}

func ListenShared(path string) (net.Listener, error) {
	oldMask := unix.Umask(0)
	defer unix.Umask(oldMask)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return l, unix.Chmod(path, 0o660)
}
