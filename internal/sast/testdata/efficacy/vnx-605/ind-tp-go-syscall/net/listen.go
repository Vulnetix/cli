package netx

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func control(network, address string, rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
~>		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

var lc = net.ListenConfig{Control: control}
