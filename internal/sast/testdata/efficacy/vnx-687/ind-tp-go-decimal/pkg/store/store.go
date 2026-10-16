package store

import "os"

func Save(dir, path string, data []byte) error {
~>	if err := os.MkdirAll(dir, 755); err != nil {
		return err
	}
~>	return os.WriteFile(path, data, 644)
}
