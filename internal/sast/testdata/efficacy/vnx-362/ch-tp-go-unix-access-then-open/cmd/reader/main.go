package main

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func dump(target string) error {
	if err := unix.Access(target, unix.R_OK); err != nil {
		return err
	}
~>	f, err := os.Open(target)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(os.Stdout, f)
	return err
}
