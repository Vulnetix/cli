package unpack

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
)

func Untar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(hdr.Mode)&0o755)
		if err != nil {
			return err
		}
		io.Copy(f, tr)
		f.Close()
	}
}
