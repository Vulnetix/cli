package keys

import "os"

func Save(f *os.File, path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	err := f.Chmod(0600)
	if err != nil {
		return err
	}
	os.Chmod(path+".pub", 0o644)
	return os.Chmod(path, 0600)
}
