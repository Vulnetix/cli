package daemon

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// Demote switches to uid:gid.
func Demote(uid, gid int) {
	var err error
	err = unix.Setresgid(gid, gid, gid)
~>	if err != nil {
		slog.Warn("setresgid failed", "err", err)
	}
	err = unix.Setresuid(uid, uid, uid)
~>	if err != nil {
		slog.Warn("setresuid failed", "err", err)
	}
}
