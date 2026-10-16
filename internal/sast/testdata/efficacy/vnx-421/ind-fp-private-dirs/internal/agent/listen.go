package agent

import (
	"net"
	"os"
	"path/filepath"
)

func Listen() (net.Listener, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return net.Listen("unix", filepath.Join(dir, "agent.sock"))
	}
	tmp, err := os.MkdirTemp("", "agent-")
	if err != nil {
		return nil, err
	}
	return net.Listen("unix", filepath.Join(tmp, "agent.sock"))
}

func ListenRun() (net.Listener, error) {
	return net.Listen("unix", "/run/agent/agent.sock")
}

func Client() (net.Conn, error) {
	return net.Dial("unix", "/tmp/agent.sock")
}
