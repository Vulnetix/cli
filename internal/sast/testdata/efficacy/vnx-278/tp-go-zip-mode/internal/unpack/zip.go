package unpack

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		path := filepath.Join(dest, filepath.Clean("/"+f.Name))
		rc, err := f.Open()
		if err != nil {
			return err
		}
~>		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
		mode := f.Mode()
~>		os.Chmod(path, mode)
	}
	return nil
}
