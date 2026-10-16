package spool

import (
	"errors"
	"os"
)

func appendJob(jobPath string, line []byte) error {
	fi, err := os.Lstat(jobPath)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("spool entry is a symlink")
	}
~>	f, err := os.OpenFile(jobPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}
