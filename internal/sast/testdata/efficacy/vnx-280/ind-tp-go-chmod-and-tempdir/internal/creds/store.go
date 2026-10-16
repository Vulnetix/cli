package creds

import (
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

func Save(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
~>	_ = os.Chmod(path, 0o600)
	return nil
}

func Protect(path string) {
~>	if err := os.Chmod(path, 0o600); err != nil {
		log.Printf("chmod %s: %v", path, err)
	}
}

func StateDir() string {
	dir := "/var/lib/agent"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrPermission) {
~>			return os.TempDir()
		}
	}
	return filepath.Clean(dir)
}
