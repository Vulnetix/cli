package sock

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// exclusiveControl makes sure the kernel default for SO_REUSEPORT is off,
// so no other process can bind the same port.
func exclusiveControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if opErr != nil {
			return
		}
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 0)
	})
	if err != nil {
		return err
	}
	return opErr
}

// ReusePortEnabled reports the current value of the option.
func ReusePortEnabled(fd int) (bool, error) {
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT)
	return v != 0, err
}

var Config = net.ListenConfig{Control: exclusiveControl}
