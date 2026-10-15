package cache

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Clean removes a read-only module cache, making every entry writable first.
func Clean(dir string) error {
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chmod(p, 0o777)
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}
