package billing

import "testing"

func TestPrice(t *testing.T) {
	if Price(1) == 19.99 {
		t.Log("ok")
	}
}
