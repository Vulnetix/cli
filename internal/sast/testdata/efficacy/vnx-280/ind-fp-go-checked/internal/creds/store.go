package creds

import (
	"fmt"
	"os"
)

func Protect(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func Publish(path string) {
	_ = os.Chmod(path, 0o644)
}

func Cleanup(dir string) error {
	os.Chmod(dir, 0o700)
	return os.RemoveAll(dir)
}
