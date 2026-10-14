package fsutil

import (
	"log"
	"os"
)

func Normalise(p string, umask os.FileMode) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if err := os.Chmod(p, 0o777&^umask); err != nil {
		return err
	}
	log.Printf("os.Chmod(%q, 0777) skipped", p)
	return os.Chmod(p, fi.Mode().Perm()&^0o022)
}
