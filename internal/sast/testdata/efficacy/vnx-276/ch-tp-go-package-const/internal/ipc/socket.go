package ipc

import (
	"net"
	"os"
)

// socketMode lets every local client connect to the control socket.
const socketMode = 0o777

// Listener wraps the control socket.
//
// The socket lives under the runtime directory and is recreated on every
// start. Stale sockets left by a crashed instance are removed first so the
// bind does not fail with EADDRINUSE.
//
// Clients connect with the CLI or with any tool that speaks the line
// protocol documented in docs/ipc.md.
type Listener struct {
	net.Listener
	path string
}

// Close removes the socket file.
func (l *Listener) Close() error {
	err := l.Listener.Close()
	_ = os.Remove(l.path)
	return err
}

// Listen opens the control socket.
func Listen(path string) (*Listener, error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
~>	if err := os.Chmod(path, socketMode); err != nil {
		l.Close()
		return nil, err
	}
	return &Listener{Listener: l, path: path}, nil
}
