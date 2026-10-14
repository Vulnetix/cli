package unpack

import (
	"archive/tar"
	"io"
	"os"
)

func write(tr *tar.Reader, hdr *tar.Header, target string) error {
	f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(hdr.Mode)&0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, tr); err != nil {
		return err
	}
	if err := os.Chmod(target, hdr.FileInfo().Mode()&^0o7022); err != nil {
		return err
	}
	return os.Chmod(target, 0o644)
}
