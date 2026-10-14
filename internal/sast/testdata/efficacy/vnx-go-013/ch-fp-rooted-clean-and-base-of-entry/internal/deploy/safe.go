package deploy

import (
	"archive/tar"
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

// Rooting the name before cleaning it removes every leading "..".
func ExtractTar(tr *tar.Reader, dest string) error {
	for {
		h, err := tr.Next()
		if err != nil {
			return nil
		}
		target := filepath.Join(dest, filepath.Clean("/"+h.Name))
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		io.Copy(f, tr)
		f.Close()
	}
}

// Flatten keeps only the file name of every entry.
func Flatten(zr *zip.Reader, dest string) error {
	for _, f := range zr.File {
		out := filepath.Join(dest, filepath.Base(f.Name))
		w, err := os.Create(out)
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(w, rc)
		rc.Close()
		w.Close()
	}
	return nil
}
