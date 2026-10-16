package store

import "os"

func Save(dir, path string, data []byte) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return os.Chmod(path, os.FileMode(0600))
}
