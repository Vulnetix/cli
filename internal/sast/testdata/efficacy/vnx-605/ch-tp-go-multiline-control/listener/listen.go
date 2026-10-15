package listener

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func Listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(
					int(fd),
					unix.SOL_SOCKET,
~>					unix.SO_REUSEPORT,
					1,
				)
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	return lc.Listen(ctx, "tcp", addr)
}
