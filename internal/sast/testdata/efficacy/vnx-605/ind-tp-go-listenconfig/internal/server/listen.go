package server

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Listen opens a TCP listener that several worker processes can share.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(
					int(fd),
					unix.SOL_SOCKET,
~>					unix.SO_REUSEPORT,
					1,
				)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	return lc.Listen(ctx, "tcp", addr)
}

// ListenUDP opens a UDP socket shared across goroutines.
func ListenUDP(ctx context.Context, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
~>				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.ListenPacket(ctx, "udp", addr)
}
