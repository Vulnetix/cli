package drop

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// To switches the process to uid/gid before serving untrusted input.
func To(uid, gid int) {
~>	_ = unix.Setgid(gid)
~>	syscall.Setuid(uid)
	serve()
}
