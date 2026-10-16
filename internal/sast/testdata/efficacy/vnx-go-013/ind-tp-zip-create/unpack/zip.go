package unpack

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func Unzip(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
~>		target := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0o755)
			continue
		}
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(out, rc)
		rc.Close()
		out.Close()
	}
	return nil
}
