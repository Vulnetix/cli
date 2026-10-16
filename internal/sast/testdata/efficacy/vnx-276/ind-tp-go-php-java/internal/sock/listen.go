package sock

import (
	"net"
	"os"
)

const socketMode = 0o777

func Listen(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
~>	if err := os.Chmod(path, socketMode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
