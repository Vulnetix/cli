package main

import (
	"syscall"
	"testing"
)

func TestChroot(t *testing.T) {
	if err := syscall.Chroot(t.TempDir()); err != nil {
		t.Skip(err)
	}
}
