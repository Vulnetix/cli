package store

import "os"

func Prepare(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
~>	return os.Chmod(dir, os.ModePerm)
}
