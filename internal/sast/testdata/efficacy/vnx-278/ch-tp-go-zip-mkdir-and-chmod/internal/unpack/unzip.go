package unpack

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

// Unzip extracts src below dst.
func Unzip(src, dst string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, zf := range reader.File {
		path := filepath.Join(dst, zf.Name)
		if zf.FileInfo().IsDir() {
~>			os.MkdirAll(path, zf.Mode())
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
~>		if err := os.Chmod(path, zf.Mode()); err != nil {
			return err
		}
	}
	return nil
}
