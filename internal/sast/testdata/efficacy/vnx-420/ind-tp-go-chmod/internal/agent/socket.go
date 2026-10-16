package agent

import (
	"net"
	"os"
)

func ListenControl(sockPath string) (net.Listener, error) {
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
~>	if err := os.Chmod(sockPath, os.ModePerm); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
