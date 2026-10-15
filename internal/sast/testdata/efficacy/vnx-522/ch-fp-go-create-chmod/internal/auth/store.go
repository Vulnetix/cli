package auth

import (
	"os"
	"path/filepath"
)

func SaveCredentials(dir string, data []byte) error {
	path := filepath.Join(dir, "credentials.json")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}
