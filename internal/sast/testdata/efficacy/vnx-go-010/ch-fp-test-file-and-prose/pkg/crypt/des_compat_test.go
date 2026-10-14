package crypt

import (
	"crypto/des"
	"crypto/rc4"
	"testing"
)

func TestKnownAnswer(t *testing.T) {
	c, err := des.NewCipher([]byte("8bytekey"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c
	s, _ := rc4.NewCipher([]byte("Key"))
	_ = s
}
