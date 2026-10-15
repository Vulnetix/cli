package run

import (
	"os"
	"testing"
)

func TestWritePID(t *testing.T) {
	f, err := os.Create("/tmp/agent-test.pid")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}
