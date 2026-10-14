package main

import (
	"log"
	"syscall"
)

type fakeOS struct{}

func (fakeOS) Setuid(int) error { return nil }

func demote(uid, gid int) {
	if err := syscall.Setgid(gid); err != nil {
		log.Fatal(err)
	}
	err := syscall.Setuid(uid)
	if err != nil {
		log.Fatal(err)
	}
	var f fakeOS
	f.Setuid(uid)
	log.Printf("syscall.Setuid(%d) done", uid)
	defer func() {
		if err := syscall.Seteuid(uid); err != nil {
			log.Fatal(err)
		}
	}()
}
