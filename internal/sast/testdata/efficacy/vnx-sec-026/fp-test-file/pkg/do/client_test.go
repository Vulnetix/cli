package do

import "testing"

func TestClient(t *testing.T) {
	c := New("dop_v1_@@sample:[a-f0-9]{64}@@")
	if c == nil {
		t.Fatal("nil client")
	}
}
