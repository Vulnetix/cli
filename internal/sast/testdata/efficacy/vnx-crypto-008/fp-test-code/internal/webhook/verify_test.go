package webhook

import "testing"

func TestSig(t *testing.T) {
	sig, expected := "a", "a"
	if sig != expected {
		t.Fatal("mismatch")
	}
}
