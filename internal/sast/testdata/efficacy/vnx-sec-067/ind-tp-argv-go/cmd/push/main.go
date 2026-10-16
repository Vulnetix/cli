package main

import "os/exec"

func push(url string) error {
	cmd := exec.Command("curl", "-sS",
~>		"-u", "pusher:@@sample:[A-Za-z0-9]{16}@@",
		url)
	return cmd.Run()
}
