package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const ctlSocket = "/tmp/agent.sock"

func main() {
~>	ln, err := net.Listen("unix", ctlSocket)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

~>	addr := &net.UnixAddr{Name: "/tmp/agent-dgram.sock", Net: "unixgram"}
	_ = addr

~>	other, _ := net.Listen("unix", filepath.Join(os.TempDir(), "agent2.sock"))
	_ = other

~>	_ = syscall.Mkfifo("/tmp/agent.fifo", 0600)
}
