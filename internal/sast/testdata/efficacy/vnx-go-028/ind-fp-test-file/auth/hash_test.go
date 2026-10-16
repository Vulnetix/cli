package auth

import (
	"crypto/md5"
	"testing"
)

func TestLegacyFixture(t *testing.T) {
	password := "fixture"
	sum := md5.Sum([]byte(password))
	if len(sum) != 16 {
		t.Fatal("size")
	}
}
