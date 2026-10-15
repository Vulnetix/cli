package ipc

import (
	"net"
	"os"
	"path/filepath"
)

// Listen creates the control socket in a directory only we can write.
func Listen() (net.Listener, error) {
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		return nil, err
	}
	return net.Listen("unix", filepath.Join(dir, "agent.sock"))
}

func ListenRun() (net.Listener, error) {
	return net.Listen("unix", "/run/agent/agent.sock")
}

// Dial is a client; it does not create the endpoint.
func Dial() (net.Conn, error) {
	return net.Dial("unix", "/tmp/agent.sock")
}

func TCP() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
