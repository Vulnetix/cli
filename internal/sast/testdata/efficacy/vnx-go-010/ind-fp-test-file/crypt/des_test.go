package crypt

import (
	"crypto/des"
	"testing"
)

func TestKnownAnswer(t *testing.T) {
	key := []byte("12345678")
	c, err := des.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 8)
	c.Encrypt(out, []byte("abcdefgh"))
}
