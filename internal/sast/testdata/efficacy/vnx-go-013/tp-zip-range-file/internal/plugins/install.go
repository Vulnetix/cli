package plugins

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

// Install unpacks an uploaded plugin bundle into the plugins directory.
func Install(bundle, dest string) error {
	zr, err := zip.OpenReader(bundle)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
~>		path := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, 0o755)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
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
	}
	return nil
}
