package main

import (
	"log"
	"syscall"
)

func demote(uid, gid int) {
	if err := syscall.Setgid(gid); err != nil {
		log.Printf("setgid: %v", err)
		syscall.Exit(1)
	}
	if err := syscall.Setuid(uid); err != nil {
		log.Printf("setuid: %v", err)
		syscall.Exit(1)
	}
}
