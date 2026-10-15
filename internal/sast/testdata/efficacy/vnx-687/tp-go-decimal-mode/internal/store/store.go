package store

import (
	"os"
	"path/filepath"
)

func Prepare(dir string, data []byte) error {
~>	if err := os.MkdirAll(dir, 755); err != nil {
		return err
	}
~>	if err := os.WriteFile(filepath.Join(dir, "config"), data, 644); err != nil {
		return err
	}
~>	f, err := os.OpenFile(filepath.Join(dir, "log"), os.O_CREATE|os.O_WRONLY, os.FileMode(600))
	if err != nil {
		return err
	}
	return f.Close()
}
