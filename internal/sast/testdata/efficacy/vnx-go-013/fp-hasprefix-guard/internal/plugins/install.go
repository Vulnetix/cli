package plugins

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Install(bundle, dest string) error {
	zr, err := zip.OpenReader(bundle)
	if err != nil {
		return err
	}
	defer zr.Close()
	root := filepath.Clean(dest) + string(os.PathSeparator)
	for _, f := range zr.File {
		path := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(path, root) {
			return fmt.Errorf("illegal file path: %s", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}
