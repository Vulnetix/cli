package netutil

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
~>				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

func rawEnable(fd int) error {
~>	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
}
