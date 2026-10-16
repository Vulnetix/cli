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
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			info := hdr.FileInfo()
~>			if err := os.MkdirAll(target, info.Mode()); err != nil {
				return err
			}
		case tar.TypeReg:
~>			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
~>			if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil {
				return err
			}
		}
	}
}
