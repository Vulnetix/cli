package builder

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func Listen() (net.Listener, error) {
~>	return net.Listen("unix", filepath.Join(os.TempDir(), "builder.sock"))
}

func ProgressFifo() error {
~>	return syscall.Mkfifo("/tmp/builder-progress.fifo", 0600)
}

func StatusAddr() (*net.UnixAddr, error) {
~>	return net.ResolveUnixAddr("unix", "/var/tmp/builder-status.sock")
}
