package work

import "os"

// Remove deletes a read-only work tree.
func Remove(dir string) error {
	os.Chmod(dir, 0o700)
	return os.RemoveAll(dir)
}
