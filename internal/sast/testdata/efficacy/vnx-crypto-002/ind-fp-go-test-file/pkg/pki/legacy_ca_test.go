package pki

import (
	"crypto/sha1"
	"testing"
)

func TestSubjectKeyID(t *testing.T) {
	want := sha1.Sum([]byte("pub"))
	if got := subjectKeyID([]byte("pub")); string(got) != string(want[:]) {
		t.Fatal("mismatch")
	}
}
