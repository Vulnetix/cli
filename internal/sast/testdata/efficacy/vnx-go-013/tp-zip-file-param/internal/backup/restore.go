package backup

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func restoreEntry(f *zip.File, dir string) error {
~>	p := filepath.Join(dir, f.Name)
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	w, err := os.Create(p)
	if err != nil {
		return err
	}
	defer w.Close()
	_, err = io.Copy(w, rc)
	return err
}
