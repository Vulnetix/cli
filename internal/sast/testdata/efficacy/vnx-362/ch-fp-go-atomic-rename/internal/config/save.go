package config

import "os"

func Save(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, path+".bak")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
