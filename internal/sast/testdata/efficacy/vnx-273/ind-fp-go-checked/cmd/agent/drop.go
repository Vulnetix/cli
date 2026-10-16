package main

import (
	"fmt"
	"syscall"
)

func dropPrivileges(uid, gid int) error {
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	err := syscall.Setuid(uid)
	if err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	return nil
}
