package main

import "golang.org/x/sys/unix"

func dropPrivileges(uid, gid int) error {
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return err
	}
	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return err
	}
	return nil
}
