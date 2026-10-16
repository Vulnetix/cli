package store

import (
	"os"
	"path/filepath"
)

func Save(dir, name string, data []byte) error {
~>	if err := os.MkdirAll(dir, 755); err != nil {
		return err
	}
~>	return os.WriteFile(filepath.Join(dir, name), data, 644)
}
