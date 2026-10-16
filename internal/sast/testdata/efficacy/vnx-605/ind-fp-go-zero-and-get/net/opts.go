package netx

import "golang.org/x/sys/unix"

func disableReusePort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 0)
}

func reusePortEnabled(fd int) (bool, error) {
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT)
	return v != 0, err
}
