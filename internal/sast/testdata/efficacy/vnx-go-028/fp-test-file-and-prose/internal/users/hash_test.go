package users

import (
	"crypto/md5"
	"testing"
)

func TestLegacyFixture(t *testing.T) {
	password := "hunter2"
	sum := md5.Sum([]byte(password))
	if len(sum) != 16 {
		t.Fatal("bad length")
	}
}
