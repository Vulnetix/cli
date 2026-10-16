package wire

import "testing"

func TestNeverNegative(t *testing.T) {
	p := []byte{1, 2, 3, 4}
	if len(p) < 0 {
		t.Fatal("impossible")
	}
}
