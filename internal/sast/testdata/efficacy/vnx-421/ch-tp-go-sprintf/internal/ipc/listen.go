package ipc

import (
	"fmt"
	"net"
	"os"
)

func Listen() (net.Listener, error) {
~>	return net.Listen("unix", fmt.Sprintf("/tmp/agent-%d.sock", os.Getuid()))
}

var ctlPath = "/tmp/agent-ctl.sock"

func Ctl() (*net.UnixListener, error) {
~>	addr, err := net.ResolveUnixAddr("unix", ctlPath)
	if err != nil {
		return nil, err
	}
	return net.ListenUnix("unix", addr)
}
