package perm

import "os"

func Normalise(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, fi.Mode()&^os.ModeSetuid); err != nil {
		return err
	}
	return os.Chmod(path, 0o4755)
}
