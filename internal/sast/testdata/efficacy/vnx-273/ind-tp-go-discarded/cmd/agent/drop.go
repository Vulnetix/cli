package main

import (
	"golang.org/x/sys/unix"
)

func dropPrivileges(uid, gid int) {
~>	_ = unix.Setgroups([]int{gid})
~>	_ = unix.Setgid(gid)
~>	unix.Setuid(uid)
}
