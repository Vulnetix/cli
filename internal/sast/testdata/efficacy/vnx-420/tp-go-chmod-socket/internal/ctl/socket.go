package ctl

import (
	"net"
	"os"
)

func Listen(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
~>	if err := os.Chmod(path, 0o777); err != nil {
		return nil, err
	}
~>	_ = os.Chmod(path, os.ModePerm)
	return ln, nil
}
