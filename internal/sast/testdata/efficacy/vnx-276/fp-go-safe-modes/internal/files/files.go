package files

import "os"

func Write(dir, p string, b []byte, fi os.FileInfo) error {
	if err := os.MkdirAll(dir, 0777); err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0666); err != nil {
		return err
	}
	if err := os.Chmod(p, 0755); err != nil {
		return err
	}
	if err := os.Chmod(p, fi.Mode()&^0o022); err != nil {
		return err
	}
	return os.Chmod(p, fi.Mode()&os.ModePerm)
}
