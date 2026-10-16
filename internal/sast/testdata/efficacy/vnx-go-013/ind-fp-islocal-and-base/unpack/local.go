package unpack

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func Flat(tr *tar.Reader, dst string) error {
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil
		}
		if !filepath.IsLocal(hdr.Name) {
			return errors.New("unsafe entry")
		}
		f, err := os.Create(filepath.Join(dst, hdr.Name))
		if err != nil {
			return err
		}
		io.Copy(f, tr)
		f.Close()
	}
}

func Flatten(tr *tar.Reader, dst string) {
	hdr, _ := tr.Next()
	os.WriteFile(filepath.Join(dst, filepath.Base(hdr.Name)), nil, 0o644)
}
