package share

import "os"

// helperMode is an octal literal: os.Chmod keeps only its permission bits.
const helperMode = 0o4755

// Prepare makes dir a group-shared directory and strips stray setuid bits.
func Prepare(dir, bin string) error {
	if err := os.Chmod(dir, 0o775|os.ModeSetgid); err != nil {
		return err
	}
	mode := 0o4755
	if err := os.Chmod(bin, os.FileMode(mode)); err != nil {
		return err
	}
	if err := os.Chmod(bin, helperMode); err != nil {
		return err
	}
	fi, err := os.Stat(bin)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSetuid != 0 {
		return os.Chmod(bin, fi.Mode()&^os.ModeSetuid)
	}
	return nil
}
