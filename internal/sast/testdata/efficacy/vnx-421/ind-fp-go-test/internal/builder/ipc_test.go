package builder

import (
	"net"
	"testing"
)

func TestListen(t *testing.T) {
	ln, err := net.Listen("unix", "/tmp/builder-test.sock")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}
