package proto

import (
	"net"
	"testing"
)

func TestSendFrame(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		b.Write([]byte("hello"))
		b.Close()
	}()
	buf := make([]byte, 5)
	a.Read(buf)
	if string(buf) != "hello" {
		t.Fatal("bad frame")
	}
}
