package store

import (
	"os"
	"path/filepath"
)

func writeBlob(dir, name string, data []byte) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	tmp := filepath.Join(os.TempDir(), name+".partial")
	f, err := os.CreateTemp(filepath.Dir(tmp), "blob-*")
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func createExclusive(p string) (*os.File, error) {
	if _, err := os.Stat(p); err == nil {
		return nil, os.ErrExist
	}
	return os.OpenFile(p,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600)
}
