package drop

import "golang.org/x/sys/unix"

func More(uid, gid int) {
~>	unix.Setgroups([]int{gid})
~>	unix.Setresgid(gid, gid, gid)
~>	unix.Setresuid(uid, uid, uid)
~>	unix.Seteuid(uid)
	serve()
}
