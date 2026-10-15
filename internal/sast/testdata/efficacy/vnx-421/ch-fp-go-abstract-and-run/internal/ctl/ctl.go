package ctl

import (
	"net"
	"os"
	"path/filepath"
)

const legacyNote = "/tmp/ctl.sock was the old location"

func Listen() (net.Listener, error) {
	if l, err := net.Listen("unix", "@ctl-agent"); err == nil {
		return l, nil
	}
	sockPath := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "ctl.sock")
	if l, err := net.Listen("unix", sockPath); err == nil {
		return l, nil
	}
	return net.Listen("unix", "/run/ctl-agent/ctl.sock")
}
