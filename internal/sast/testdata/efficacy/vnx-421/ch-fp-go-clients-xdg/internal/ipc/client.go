package ipc

import (
	"net"
	"os"
	"path/filepath"
)

func Dial() (net.Conn, error) {
	return net.Dial("unix", "/tmp/agent.sock")
}

func Serve() (net.Listener, error) {
	dir, err := os.MkdirTemp("", "agent-")
	if err != nil {
		return nil, err
	}
	if _, err := net.Listen("unix", filepath.Join(dir, "agent.sock")); err != nil {
		return nil, err
	}
	return net.Listen("unix", filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "agent.sock"))
}
