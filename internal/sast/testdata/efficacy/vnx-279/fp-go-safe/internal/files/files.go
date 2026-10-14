package files

import "os"

func Harden(p string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSetuid != 0 {
		return os.Chmod(p, fi.Mode()&^os.ModeSetuid)
	}
	return os.Chmod(p, 0o755)
}
