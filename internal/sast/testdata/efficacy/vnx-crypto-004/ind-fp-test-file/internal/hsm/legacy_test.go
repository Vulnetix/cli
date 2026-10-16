package hsm

import (
	"crypto/des"
	"testing"
)

func TestTripleDES(t *testing.T) {
	key := make([]byte, 24)
	if _, err := des.NewTripleDESCipher(key); err != nil {
		t.Fatal(err)
	}
}
