package unpack

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
)

// Untar writes the archive in r below dst.
func Untar(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
~>			if err := os.MkdirAll(target, info.Mode()); err != nil {
				return err
			}
			continue
		}
~>		f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
}
