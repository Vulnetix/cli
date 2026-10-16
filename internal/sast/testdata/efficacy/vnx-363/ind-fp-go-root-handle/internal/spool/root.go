package spool

import (
	"errors"
	"os"
)

// Writes go through an os.Root so a swapped link cannot escape the spool.
func appendJobRoot(root *os.Root, name string, line []byte) error {
	fi, err := root.Lstat(name)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("spool entry is a symlink")
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}
