package priv

import (
	"log"

	"golang.org/x/sys/unix"
)

func More(uid, gid int, jail string) {
~>	if err := unix.Chroot(jail); err != nil {
		log.Println(err)
	}
~>	if err := unix.Setgroups(nil); err != nil {
		log.Println(err)
	}
~>	if err := unix.Setresuid(uid, uid, uid); err != nil {
		log.Println(err)
	}
	serve()
}
